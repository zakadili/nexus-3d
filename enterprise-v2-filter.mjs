/**
 * Pure filtering helper for the UI preview. Accepts display-only demo records;
 * no customer inventory or intelligence observations are loaded here.
 */
export function matchesDemoRecord(record, query = '', selectedSeverity = 'all') {
  const normalizedQuery = String(query).trim().toLocaleLowerCase();
  const normalizedSeverity = String(selectedSeverity).trim().toLocaleLowerCase();
  const actualSeverity = String(record.severity ?? '').trim().toLocaleLowerCase();
  const displayText = String(record.text ?? '').toLocaleLowerCase();
  return (normalizedSeverity === 'all' || actualSeverity === normalizedSeverity)
    && (!normalizedQuery || displayText.includes(normalizedQuery));
}
