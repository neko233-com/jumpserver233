// datetime-local canonical values omit a zero seconds component. Playwright
// verifies the assigned value exactly, so use that same browser representation.
export function normalizeDateTimeLocal(value: string): string {
  return value.replace(/(T\d{2}:\d{2}):00$/, "$1");
}
