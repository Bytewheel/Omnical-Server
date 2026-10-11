//! Portal web-calendar grid tests (PLAN_NEXT_AGENT_WEB_CALENDAR_UI.md §5):
//! the membership-only listing, the write gate (`can_write &&
//! !is_read_only`) behind form visibility and the mutating handlers, the
//! POST→Redirect→GET cycle for create/edit/delete, and a read-only tasks-list
//! smoke check.
use super::{ResponseExtractString, get_app};
use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::header::CONTENT_TYPE;
use http::{Method, StatusCode};
use rstest::rstest;
use rustical_ical::{CalendarObject, CalendarObjectType};
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType, Privilege};
use rustical_store::{
    Addressbook, AddressbookReadStore, AddressbookWriteStore, Calendar, CalendarMetadata,
    CalendarReadStore, CalendarWriteStore, CollectionShareStore,
};
use rustical_store_sqlite::{
    SqliteCollectionShareStore,
    tests::{TestStoreContext, test_store_context},
};
use tower::ServiceExt;

const EVENT_ICS: &str = r"
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//omnical test//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:9999-grid-seed@test
DTSTAMP:20260301T120000Z
DTSTART:20260315T090000Z
DTEND:20260315T100000Z
SUMMARY:{summary}
END:VEVENT
END:VCALENDAR";

async fn insert_group(
    context: &TestStoreContext,
    group_id: &str,
    owner: &str,
    member: Option<&str>,
) {
    context
        .principal_store
        .insert_principal(
            Principal {
                id: group_id.to_owned(),
                displayname: Some(group_id.to_owned()),
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Group,
                needs_password_change: false,
                privileges: Default::default(),
            },
            false,
        )
        .await
        .unwrap();
    context
        .principal_store
        .set_group_owner(group_id, owner)
        .await
        .unwrap();
    context
        .principal_store
        .add_membership(owner, group_id)
        .await
        .unwrap();
    if let Some(member) = member {
        context
            .principal_store
            .add_membership(member, group_id)
            .await
            .unwrap();
    }
}

async fn insert_user(context: &TestStoreContext, id: &str) {
    context
        .principal_store
        .insert_principal(
            Principal {
                id: id.to_owned(),
                displayname: Some(id.to_owned()),
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Individual,
                needs_password_change: false,
                privileges: Default::default(),
            },
            false,
        )
        .await
        .unwrap();
    context
        .principal_store
        .add_app_token(id, id.to_owned(), id.to_owned())
        .await
        .unwrap();
}

async fn insert_calendar(
    context: &TestStoreContext,
    principal: &str,
    id: &str,
    displayname: &str,
    components: Vec<CalendarObjectType>,
) {
    context
        .cal_store
        .insert_calendar(Calendar {
            id: id.to_owned(),
            principal: principal.to_owned(),
            meta: CalendarMetadata {
                displayname: Some(displayname.to_owned()),
                order: 0,
                description: None,
                color: Some("#00ff00".to_owned()),
            },
            timezone_id: Some("UTC".to_owned()),
            deleted_at: None,
            synctoken: 0,
            subscription_url: None,
            push_topic: format!("webgrid-{id}"),
            components,
        })
        .await
        .unwrap();
}

async fn insert_event(
    context: &TestStoreContext,
    principal: &str,
    cal_id: &str,
    object_id: &str,
    summary: &str,
) {
    let object =
        CalendarObject::from_ics(EVENT_ICS.replace("{summary}", summary)).expect("parse event");
    context
        .cal_store
        .put_object(principal, cal_id, object_id, object, false)
        .await
        .unwrap();
}

/// The grid month everything in this module pins to, so tests never depend
/// on the wall-clock month the runner executes in.
const GRID_MONTH: &str = "2026-03";

fn request(
    method: Method,
    uri: &str,
    user: &str,
    pass: &str,
    body: Option<String>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "public.example")
        .header("cookie", "tzid=UTC");
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    let mut request = builder
        .body(body.map_or_else(Body::empty, Body::from))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic(user, pass));
    request
}

fn single_grid(owner: &str, cal: &str) -> String {
    format!("/frontend/user/{owner}/calendar/{cal}/events?date={GRID_MONTH}")
}

/// The live test user is a member of `teamgroup` (default edit privilege) and
/// `viewgroup` (demoted to view), and not a member of `othergroup` (owned by
/// `bob`). Calendars: `personal` (user), `teamcal`, `viewcal`, `secretcal`.
async fn setup_fixtures(context: &TestStoreContext) {
    insert_user(context, "bob").await;
    insert_group(context, "teamgroup", "bob", Some("user")).await;
    insert_group(context, "viewgroup", "bob", Some("user")).await;
    insert_group(context, "othergroup", "bob", None).await;

    insert_calendar(
        context,
        "user",
        "personal",
        "Personal",
        vec![CalendarObjectType::Event, CalendarObjectType::Todo],
    )
    .await;
    insert_calendar(
        context,
        "teamgroup",
        "teamcal",
        "Team Calendar",
        vec![CalendarObjectType::Event],
    )
    .await;
    insert_calendar(
        context,
        "viewgroup",
        "viewcal",
        "View Only",
        vec![CalendarObjectType::Event],
    )
    .await;
    insert_calendar(
        context,
        "othergroup",
        "secretcal",
        "Secret",
        vec![CalendarObjectType::Event],
    )
    .await;

    insert_event(context, "user", "personal", "own-1", "Vacation planning").await;
    insert_event(context, "teamgroup", "teamcal", "team-1", "Team standup").await;
    insert_event(context, "viewgroup", "viewcal", "view-1", "Internal notes").await;
    insert_event(
        context,
        "othergroup",
        "secretcal",
        "secret-1",
        "Bob's secret",
    )
    .await;

    context
        .principal_store
        .set_privilege("user", "viewgroup", Privilege::View)
        .await
        .unwrap();
}

async fn grid_body(app: &axum::Router, uri: &str) -> String {
    let resp = app
        .clone()
        .oneshot(request(Method::GET, uri, "user", "pass", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET {uri}");
    resp.extract_string().await
}

#[rstest]
#[tokio::test]
async fn test_grid_lists_only_membership_calendars(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let app = get_app(context);

    let body = grid_body(
        &app,
        &format!("/frontend/user/user/events?date={GRID_MONTH}"),
    )
    .await;
    assert!(body.contains("Team standup"), "member calendar event shown");
    assert!(
        body.contains("Vacation planning"),
        "own calendar event shown"
    );
    assert!(
        body.contains("Internal notes"),
        "view-privilege event shown"
    );
    assert!(
        !body.contains("Bob's secret"),
        "non-member calendar never listed"
    );
    assert!(
        !body.contains("Secret"),
        "non-member calendar chip never rendered"
    );

    // The single-calendar grid of a non-member calendar is 401, matching the
    // Calendars tab's per-calendar gate.
    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            &single_grid("othergroup", "secretcal"),
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The member's own single-calendar grid works and offers creation.
    let body = grid_body(&app, &single_grid("user", "personal")).await;
    assert!(body.contains("Vacation planning"), "own single grid event");
    assert!(body.contains("New event"), "own single grid create button");

    // The Path user must match the authenticated user.
    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/bob/events",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[tokio::test]
async fn test_form_visibility_follows_write_privilege(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let app = get_app(context);

    // View-privilege calendar: grid is readable but offers no New-event form.
    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            &single_grid("viewgroup", "viewcal"),
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(
        body.contains("Internal notes"),
        "view-only grid event shown"
    );
    assert!(
        !body.contains("New event"),
        "view-only grid hides the create button"
    );

    // The new-event form and the create POST are both hard-gated.
    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/viewgroup/calendar/viewcal/events/new",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/viewgroup/calendar/viewcal/events",
            "user",
            "pass",
            Some(
                "summary=Sneaky&start_date=2026-03-15&start_time=09%3A00&end_date=2026-03-15&end_time=10%3A00&timezone=UTC"
                    .to_owned(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The view-only member cannot open the edit form either.
    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/viewgroup/calendar/viewcal/events/view-1/edit",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The aggregate grid has exactly one writable calendar (teamcal), so the
    // New-event button appears once.
    let body = grid_body(
        &app,
        &format!("/frontend/user/user/events?date={GRID_MONTH}"),
    )
    .await;
    assert_eq!(
        body.matches("New event").count(),
        1,
        "single writable calendar renders one create button"
    );
}

/// POST create/edit/delete → 303 to the grid → GET shows the change; editing
/// preserves the object's UID.
#[rstest]
#[tokio::test]
async fn test_event_crud_post_redirect_get(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let app = get_app(context.clone());

    // Create.
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/teamgroup/calendar/teamcal/events",
            "user",
            "pass",
            Some(
                "summary=Kickoff&start_date=2026-03-15&start_time=09%3A00&end_date=2026-03-15&end_time=10%3A00&timezone=UTC"
                    .to_owned(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/frontend/user/teamgroup/calendar/teamcal/events"
    );

    let objects = context
        .cal_store
        .get_objects("teamgroup", "teamcal")
        .await
        .unwrap();
    let (object_id, created) = objects
        .iter()
        .find(|(_, o)| o.get_ics().contains("SUMMARY:Kickoff"))
        .expect("created object present");
    assert!(created.get_uid().ends_with("@omnical"), "fresh uid minted");
    let created_uid = created.get_uid().to_owned();

    let body = grid_body(&app, &single_grid("teamgroup", "teamcal")).await;
    assert!(body.contains("Kickoff"), "grid shows created event");
    assert!(body.contains("09:00"), "timed event renders its start time");

    // Edit form prefills the stored event.
    let uri = format!("/frontend/user/teamgroup/calendar/teamcal/events/{object_id}/edit");
    let resp = app
        .clone()
        .oneshot(request(Method::GET, &uri, "user", "pass", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let form_body = resp.extract_string().await;
    assert!(
        form_body.contains("value=\"Kickoff\""),
        "edit form prefilled"
    );

    // Update.
    let uri = format!("/frontend/user/teamgroup/calendar/teamcal/events/{object_id}");
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &uri,
            "user",
            "pass",
            Some(
                "summary=Kickoff widened&start_date=2026-03-15&start_time=09%3A00&end_date=2026-03-15&end_time=11%3A00&timezone=UTC"
                    .to_owned(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let updated = context
        .cal_store
        .get_object("teamgroup", "teamcal", object_id, false)
        .await
        .unwrap();
    assert_eq!(
        updated.get_uid(),
        created_uid,
        "update preserves the event uid"
    );

    let body = grid_body(&app, &single_grid("teamgroup", "teamcal")).await;
    assert!(body.contains("Kickoff widened"), "grid shows updated event");
    assert!(!body.contains(">Kickoff<"), "old title replaced");

    // Delete → trashbin.
    let uri = format!("/frontend/user/teamgroup/calendar/teamcal/events/{object_id}/delete");
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &uri,
            "user",
            "pass",
            Some(String::new()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    assert!(
        context
            .cal_store
            .get_object("teamgroup", "teamcal", object_id, false)
            .await
            .is_err(),
        "deleted object gone from the live set"
    );
    let body = grid_body(&app, &single_grid("teamgroup", "teamcal")).await;
    assert!(
        !body.contains("Kickoff"),
        "grid no longer shows deleted event"
    );
}

#[rstest]
#[tokio::test]
async fn test_tasks_list_and_hide_completed(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;

    let todo = CalendarObject::from_ics(
        "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//omnical test//EN
BEGIN:VTODO
UID:todo-open@test
DTSTAMP:20260301T120000Z
DUE;VALUE=DATE:20260320
SUMMARY:Buy milk
STATUS:NEEDS-ACTION
END:VTODO
END:VCALENDAR"
            .to_owned(),
    )
    .unwrap();
    let done = CalendarObject::from_ics(
        "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//omnical test//EN
BEGIN:VTODO
UID:todo-done@test
DTSTAMP:20260301T120000Z
DUE;VALUE=DATE:20260305
SUMMARY:File taxes
STATUS:COMPLETED
PERCENT-COMPLETE:100
END:VTODO
END:VCALENDAR"
            .to_owned(),
    )
    .unwrap();
    context
        .cal_store
        .put_object("user", "personal", "todo-1", todo, false)
        .await
        .unwrap();
    context
        .cal_store
        .put_object("user", "personal", "todo-2", done, false)
        .await
        .unwrap();
    let recurring = CalendarObject::from_ics(
        "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//omnical test//EN
BEGIN:VTODO
UID:todo-recurring@test
DTSTAMP:20260301T120000Z
DTSTART:20260301T090000Z
SUMMARY:Water plants
RRULE:FREQ=WEEKLY
STATUS:NEEDS-ACTION
END:VTODO
END:VCALENDAR"
            .to_owned(),
    )
    .unwrap();
    context
        .cal_store
        .put_object("user", "personal", "todo-3", recurring, false)
        .await
        .unwrap();

    let app = get_app(context);

    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/tasks",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Buy milk"), "open task listed");
    assert!(
        body.contains("File taxes"),
        "completed task listed by default"
    );
    assert!(body.contains("2026-03-20"), "date due rendered");
    assert!(body.contains("NEEDS-ACTION"), "status chip rendered");
    assert!(
        body.contains("Water plants"),
        "recurring task listed as its master"
    );
    assert_eq!(
        body.matches(">Recurring<").count(),
        1,
        "recurring chip on exactly the recurring task"
    );

    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/tasks?hide_completed=on",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Buy milk"), "open task still listed");
    assert!(!body.contains("File taxes"), "completed task hidden");
}

/// POST create/edit/delete a task → 303 to the tasks list → GET shows the
/// change; view-only calendars can neither create nor edit.
#[rstest]
#[tokio::test]
async fn test_tasks_crud_post_redirect_get(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    insert_calendar(
        &context,
        "viewgroup",
        "viewtasks",
        "View Tasks",
        vec![CalendarObjectType::Todo],
    )
    .await;
    let view_task = CalendarObject::from_ics(
        "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//omnical test//EN
BEGIN:VTODO
UID:view-task@test
DTSTAMP:20260301T120000Z
SUMMARY:Viewers only task
STATUS:NEEDS-ACTION
END:VTODO
END:VCALENDAR"
            .to_owned(),
    )
    .unwrap();
    context
        .cal_store
        .put_object("viewgroup", "viewtasks", "vt-1", view_task, false)
        .await
        .unwrap();

    let app = get_app(context.clone());

    // Create through the aggregate form's calendar picker (personal).
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/tasks",
            "user",
            "pass",
            Some(
                "calendar=user%7Cpersonal&summary=Groceries&status=IN-PROCESS&due_date=2026-03-21"
                    .to_owned(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/frontend/user/user/tasks"
    );

    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/tasks",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    let list_body = resp.extract_string().await;
    assert!(list_body.contains("Groceries"), "created task listed");
    assert!(list_body.contains("IN-PROCESS"), "status chip rendered");
    assert!(
        list_body.contains("Viewers only task"),
        "view-only task still listed"
    );
    assert!(
        !list_body.contains("/frontend/user/viewgroup/calendar/viewtasks/tasks/"),
        "view-only task renders no edit link"
    );

    // The view-only calendar cannot be written through the aggregate form.
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/tasks",
            "user",
            "pass",
            Some("calendar=viewgroup%7Cviewtasks&summary=Sneaky".to_owned()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Edit prefill.
    let (object_id, _) = context
        .cal_store
        .get_objects("user", "personal")
        .await
        .unwrap()
        .into_iter()
        .find(|(_, o)| o.get_ics().contains("SUMMARY:Groceries"))
        .expect("created task present");
    let uri = format!("/frontend/user/user/calendar/personal/tasks/{object_id}/edit");
    let resp = app
        .clone()
        .oneshot(request(Method::GET, &uri, "user", "pass", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let form_body = resp.extract_string().await;
    assert!(
        form_body.contains("value=\"Groceries\""),
        "task form prefilled"
    );

    // Update to completed.
    let uri = format!("/frontend/user/user/calendar/personal/tasks/{object_id}");
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &uri,
            "user",
            "pass",
            Some(
                "calendar=user%7Cpersonal&summary=Groceries&status=COMPLETED&due_date=2026-03-21"
                    .to_owned(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/tasks?hide_completed=on",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    let body = resp.extract_string().await;
    assert!(!body.contains("Groceries"), "completed task hidden");

    // Delete.
    let uri = format!("{uri}/delete");
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &uri,
            "user",
            "pass",
            Some(String::new()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/tasks",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    let body = resp.extract_string().await;
    assert!(!body.contains("Groceries"), "deleted task gone");
}

/// POST create/edit/delete a contact → 303 to the contacts list → GET shows
/// the change; non-members get 401 on the form and the mutating routes.
#[rstest]
#[tokio::test]
async fn test_contacts_crud_post_redirect_get(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    context
        .addr_store
        .insert_addressbook(Addressbook {
            id: "people".to_owned(),
            principal: "user".to_owned(),
            displayname: Some("People".to_owned()),
            description: None,
            deleted_at: None,
            synctoken: 0,
            push_topic: "webgrid-people".to_owned(),
        })
        .await
        .unwrap();

    let app = get_app(context.clone());

    // Create.
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/addressbook/people/contacts",
            "user",
            "pass",
            Some("name=Alice&email=alice%40example.com&phone=1234".to_owned()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/frontend/user/user/addressbook/people/contacts"
    );

    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/addressbook/people/contacts",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    let body = resp.extract_string().await;
    assert!(body.contains("Alice"), "created contact listed");
    assert!(body.contains("alice@example.com"), "email shown");
    assert!(body.contains("New contact"), "create button shown");

    let (object_id, created) =
        AddressbookReadStore::get_objects(&context.addr_store, "user", "people")
            .await
            .unwrap()
            .into_iter()
            .find(|(_, o)| o.get_vcf().contains("FN:Alice"))
            .expect("created contact present");
    assert_eq!(
        created.get_vcard().get_uid(),
        Some(format!("{object_id}@omnical").as_str()),
        "fresh uid minted"
    );

    // Edit prefill + update.
    let uri = format!("/frontend/user/user/addressbook/people/contacts/{object_id}/edit");
    let resp = app
        .clone()
        .oneshot(request(Method::GET, &uri, "user", "pass", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let form_body = resp.extract_string().await;
    assert!(
        form_body.contains("value=\"Alice\""),
        "contact form prefilled"
    );

    let uri = format!("/frontend/user/user/addressbook/people/contacts/{object_id}");
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &uri,
            "user",
            "pass",
            Some("name=Alice+Bee&email=alice%40example.com&phone=5678".to_owned()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let updated =
        AddressbookReadStore::get_object(&context.addr_store, "user", "people", &object_id, false)
            .await
            .unwrap();
    assert_eq!(
        updated.get_vcard().get_uid(),
        created.get_vcard().get_uid(),
        "update preserves the contact uid"
    );

    // Delete.
    let uri = format!("/frontend/user/user/addressbook/people/contacts/{object_id}/delete");
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &uri,
            "user",
            "pass",
            Some(String::new()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        AddressbookReadStore::get_object(&context.addr_store, "user", "people", &object_id, false)
            .await
            .is_err(),
        "deleted contact gone from the live set"
    );

    // Bob is not `user`, so every one of these routes rejects him.
    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/addressbook/people/contacts/new",
            "bob",
            "bob",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/addressbook/people/contacts",
            "bob",
            "bob",
            Some("name=Evil".to_owned()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// §6 follow-up 1: with no `tzid` cookie the single-calendar grid falls back
/// to the calendar's own timezone for UTC instances, and only then to UTC.
#[rstest]
#[tokio::test]
async fn test_grid_timezone_fallback_is_the_calendar_zone(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    insert_calendar(
        &context,
        "user",
        "berlin",
        "Berlin",
        vec![CalendarObjectType::Event],
    )
    .await;
    context
        .cal_store
        .update_calendar(
            "user",
            "berlin",
            Calendar {
                id: "berlin".to_owned(),
                principal: "user".to_owned(),
                meta: CalendarMetadata {
                    displayname: Some("Berlin".to_owned()),
                    order: 0,
                    description: None,
                    color: None,
                },
                timezone_id: Some("Europe/Berlin".to_owned()),
                deleted_at: None,
                synctoken: 0,
                subscription_url: None,
                push_topic: "webgrid-berlin".to_owned(),
                components: vec![CalendarObjectType::Event],
            },
        )
        .await
        .unwrap();
    let event = CalendarObject::from_ics(
        "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//omnical test//EN
BEGIN:VEVENT
UID:berlin-event@test
DTSTAMP:20260301T120000Z
DTSTART:20260315T090000Z
DTEND:20260315T100000Z
SUMMARY:Berlin morning call
END:VEVENT
END:VCALENDAR"
            .to_owned(),
    )
    .unwrap();
    context
        .cal_store
        .put_object("user", "berlin", "be-1", event, false)
        .await
        .unwrap();

    let app = get_app(context);

    // No tzid cookie: 09:00Z renders as 10:00 in Europe/Berlin (CET).
    let uri = "/frontend/user/user/calendar/berlin/events?date=2026-03";
    let mut no_tzid_request = request(Method::GET, uri, "user", "pass", None);
    no_tzid_request.headers_mut().insert(
        http::header::COOKIE,
        http::HeaderValue::from_static("lang=en"),
    );
    let resp = app.clone().oneshot(no_tzid_request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(
        body.contains("Times shown in Europe/Berlin"),
        "calendar zone shown in the times note"
    );
    assert!(
        body.contains("10:00"),
        "UTC event mapped into the calendar zone"
    );

    // With a tzid cookie the browser zone wins.
    let resp = app
        .clone()
        .oneshot(request(Method::GET, uri, "user", "pass", None))
        .await
        .unwrap();
    let body = resp.extract_string().await;
    assert!(
        body.contains("Times shown in UTC"),
        "browser zone overrides the calendar zone"
    );
    assert!(body.contains("09:00"), "UTC in the UTC zone stays 09:00");
}

fn extract_code_body(body: &str, marker: &str) -> String {
    let start = body.find(marker).expect(marker) + marker.len();
    let rest = &body[start..];
    let end = rest.find("</code>").expect("code end");
    rest[..end].to_owned()
}

/// §17.12.1: minting full-access CardDAV credentials for an addressbook
/// grants a guest principal real read/write/delete access through the
/// CardDAV surface (the store resolves the share on every operation), and
/// revocation takes that access away again.
#[rstest]
#[tokio::test]
async fn test_addressbook_credentials_grant_full_crud(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    context
        .addr_store
        .insert_addressbook(Addressbook {
            id: "people".to_owned(),
            principal: "user".to_owned(),
            displayname: Some("People".to_owned()),
            description: None,
            deleted_at: None,
            synctoken: 0,
            push_topic: "webgrid-people".to_owned(),
        })
        .await
        .unwrap();

    let app = get_app(context.clone());

    // The Addressbooks screen offers the generate button on the own tile.
    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/addressbook",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    let body = resp.extract_string().await;
    assert!(
        body.contains("Generate credentials"),
        "own addressbook tile offers credential minting"
    );

    // Mint.
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/addressbook/credentials",
            "user",
            "pass",
            Some("principal=user&addressbook_id=people".to_owned()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(
        body.contains("Addressbook credentials generated!"),
        "one-time banner shown"
    );
    let guest = extract_code_body(&body, "Username: <code>");
    let token = extract_code_body(&body, "App token: <code>");
    assert!(guest.starts_with("guest-"), "guest principal minted");
    assert!(body.contains("carddav"), "server URL shown");

    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let shares = share_store
        .get_shares_for_collection("user", "people")
        .await
        .unwrap();
    assert_eq!(shares.len(), 1, "one active share row");
    assert_eq!(shares[0].guest_principal, guest);
    let share_id = shares[0].id.clone();

    // Full CRUD over CardDAV as the guest.
    let addr_url = format!("/carddav/principal/{guest}/people");
    let vcard = "BEGIN:VCARD
VERSION:4.0
FN:Cyrus Daboo
N:Daboo;Cyrus;;;
EMAIL:cyrus@example.com
UID:cyrus-uid-1
END:VCARD";
    let vcard_updated = "BEGIN:VCARD
VERSION:4.0
FN:Cyrus Changed
N:Changed;Cyrus;;;
EMAIL:cyrus@example.com
UID:cyrus-uid-1
END:VCARD";

    let mut propfind = Request::builder()
        .method("PROPFIND")
        .uri(format!("/carddav/principal/{guest}"))
        .body(Body::empty())
        .unwrap();
    propfind
        .headers_mut()
        .typed_insert(Authorization::basic(&guest, &token));
    let resp = app.clone().oneshot(propfind).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = resp.extract_string().await;
    assert!(
        body.contains("/people"),
        "shared addressbook listed for guest"
    );

    let mut put = Request::builder()
        .method("PUT")
        .uri(format!("{addr_url}/cyrus.vcf"))
        .header("If-None-Match", "*")
        .header("Content-Type", "text/vcard")
        .body(Body::from(vcard))
        .unwrap();
    put.headers_mut()
        .typed_insert(Authorization::basic(&guest, &token));
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "guest can create");

    let mut put = Request::builder()
        .method("PUT")
        .uri(format!("{addr_url}/cyrus.vcf"))
        .body(Body::from(vcard_updated))
        .unwrap();
    put.headers_mut()
        .typed_insert(Authorization::basic(&guest, &token));
    let resp = app.clone().oneshot(put).await.unwrap();
    assert!(
        resp.status().is_success(),
        "guest can update — got {}",
        resp.status()
    );

    let mut get = Request::builder()
        .method("GET")
        .uri(format!("{addr_url}/cyrus.vcf"))
        .body(Body::empty())
        .unwrap();
    get.headers_mut()
        .typed_insert(Authorization::basic(&guest, &token));
    let resp = app.clone().oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(
        body.contains("Cyrus Changed"),
        "guest wrote under the owner"
    );

    // The owner sees the guest's contact through the portal list.
    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/addressbook/people/contacts",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    let body = resp.extract_string().await;
    assert!(
        body.contains("Cyrus Changed"),
        "owner sees the guest's write"
    );

    // Guest delete.
    let mut delete = Request::builder()
        .method("DELETE")
        .uri(format!("{addr_url}/cyrus.vcf"))
        .body(Body::empty())
        .unwrap();
    delete
        .headers_mut()
        .typed_insert(Authorization::basic(&guest, &token));
    let resp = app.clone().oneshot(delete).await.unwrap();
    assert!(resp.status().is_success(), "guest can delete");

    // Revoke through the portal, then the guest loses everything.
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/frontend/user/user/addressbook/credentials/{share_id}/revoke"),
            "user",
            "pass",
            Some("principal=user".to_owned()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let mut propfind = Request::builder()
        .method("PROPFIND")
        .uri(format!("/carddav/principal/{guest}"))
        .body(Body::empty())
        .unwrap();
    propfind
        .headers_mut()
        .typed_insert(Authorization::basic(&guest, &token));
    let resp = app.clone().oneshot(propfind).await.unwrap();
    let body = resp.extract_string().await;
    assert!(
        !body.contains("/people"),
        "revoked guest no longer sees the addressbook"
    );

    let mut put = Request::builder()
        .method("PUT")
        .uri(format!("{addr_url}/back.vcf"))
        .header("If-None-Match", "*")
        .header("Content-Type", "text/vcard")
        .body(Body::from(vcard))
        .unwrap();
    put.headers_mut()
        .typed_insert(Authorization::basic(&guest, &token));
    let resp = app.clone().oneshot(put).await.unwrap();
    assert!(
        matches!(
            resp.status(),
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
        ),
        "revoked guest cannot write — got {}",
        resp.status()
    );

    // Non-owners cannot mint credentials for someone else's addressbook.
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/bob/addressbook/credentials",
            "bob",
            "bob",
            Some("principal=user&addressbook_id=people".to_owned()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
