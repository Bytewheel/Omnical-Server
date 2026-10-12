use super::prop::{
    CalendarData, CalendarObjectProp, CalendarObjectPropName, CalendarObjectPropWrapper,
    CalendarObjectPropWrapperName,
};
use crate::Error;
use caldata::generator::Emitter;
use rustical_dav::{
    extensions::CommonPropertiesExtension,
    privileges::UserPrivilegeSet,
    resource::{PrincipalUri, Resource, ResourceName},
    resourcetype,
    xml::Resourcetype,
};
use rustical_ical::CalendarObject;
use rustical_store::auth::Principal;
use std::borrow::Cow;

#[derive(Clone)]
pub struct CalendarObjectResource {
    pub object: CalendarObject,
    pub object_id: String,
    pub principal: String,
    /// Omnical §18.37: the per-request `DailyView` shim context. `Some` on
    /// the REPORT paths (where the phone consumes `<C:calendar-data/>`);
    /// `None` — every PROPFIND path — serves canonical bytes.
    pub dailyview: Option<crate::dailyview::DailyviewContext>,
}

impl ResourceName for CalendarObjectResource {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from(format!("{}.ics", self.object_id))
    }
}

impl Resource for CalendarObjectResource {
    type Prop = CalendarObjectPropWrapper;
    type Error = Error;
    type Principal = Principal;

    fn is_collection(&self) -> bool {
        false
    }

    fn get_resourcetype(&self) -> Resourcetype {
        resourcetype!()
    }

    fn get_prop(
        &self,
        puri: &impl PrincipalUri,
        user: &Principal,
        prop: &CalendarObjectPropWrapperName,
    ) -> Result<Self::Prop, Self::Error> {
        Ok(match prop {
            CalendarObjectPropWrapperName::CalendarObject(prop) => {
                CalendarObjectPropWrapper::CalendarObject(match prop {
                    CalendarObjectPropName::Getetag => {
                        CalendarObjectProp::Getetag(self.object.get_etag())
                    }
                    CalendarObjectPropName::CalendarData(CalendarData { expand, .. }) => {
                        CalendarObjectProp::CalendarData(expand.as_ref().map_or_else(
                            // Omnical §18.37: the phone files each fetched body
                            // at its master's `DTSTART` with no recurrence
                            // expansion — serve it the first concrete
                            // occurrence inside its own 4-day window (and the
                            // §18.36 all-day form) instead. Every other
                            // client, and an unarmed shim, keep the canonical
                            // serialization.
                            || {
                                self.dailyview.as_ref().map_or_else(
                                    || self.object.get_ics().to_owned(),
                                    |context| {
                                        crate::dailyview::rewrite_for_dailyview(
                                            &self.object,
                                            context,
                                        )
                                        .into_owned()
                                    },
                                )
                            },
                            // CALDAV:expand keeps RFC 4791 §10.6 semantics — untouched.
                            |expand| {
                                self.object
                                    .get_inner()
                                    .expand_recurrence(
                                        Some(expand.start.to_utc()),
                                        Some(expand.end.to_utc()),
                                    )
                                    .generate()
                            },
                        ))
                    }
                    CalendarObjectPropName::Getcontenttype => {
                        CalendarObjectProp::Getcontenttype("text/calendar;charset=utf-8")
                    }
                })
            }
            CalendarObjectPropWrapperName::Common(prop) => CalendarObjectPropWrapper::Common(
                CommonPropertiesExtension::get_prop(self, puri, user, prop)?,
            ),
        })
    }

    fn get_displayname(&self) -> Option<&str> {
        None
    }

    fn get_owner(&self) -> Option<&str> {
        Some(&self.principal)
    }

    fn get_etag(&self) -> Option<String> {
        Some(self.object.get_etag())
    }

    fn get_user_privileges(&self, user: &Principal) -> Result<UserPrivilegeSet, Self::Error> {
        // Omnical §17.9.2: `view` members read but cannot write.
        if !user.is_principal(&self.principal) {
            return Ok(UserPrivilegeSet::default());
        }
        if user.can_write(&self.principal) {
            Ok(UserPrivilegeSet::all())
        } else {
            Ok(UserPrivilegeSet::read_only())
        }
    }
}
