let holidaysPromise = null

// The create-calendar modal's "add holidays" dropdown reads its groups and
// sets from the deployment's holidays.toml manifest (served as public
// metadata, like the timezone list — names only, nothing user-specific).
// Cached per page load: the manifest changes only on a deploy.
export async function getHolidays() {
  holidaysPromise ||= new Promise(async (resolve, reject) => {
    try {
      let response = await fetch('/frontend/_holidays.json')
      let list = await response.json()
      resolve(list.groups || [])
    } catch (e) {
      reject(e)
    }
  })
  return await holidaysPromise
}
