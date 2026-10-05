import { buildReadableRows, humanizeLabel } from '../vpReadable';

describe('humanizeLabel', () => {
  it('maps well-known JWT/VC keys to plain English', () => {
    expect(humanizeLabel('iss')).toBe('Issuer');
    expect(humanizeLabel('verifiableCredential')).toBe('Credentials');
    expect(humanizeLabel('workloadBinding')).toBe('Workload binding');
    expect(humanizeLabel('policy_id')).toBe('Policy package');
    expect(humanizeLabel('policy_definition_id')).toBe('Policy definition ID');
  });

  it('humanizes camelCase and snake_case keys', () => {
    expect(humanizeLabel('camelCaseKey')).toBe('Camel Case Key');
    expect(humanizeLabel('some_snake_case')).toBe('Some snake case');
  });
});

describe('buildReadableRows', () => {
  it('formats DIDs as monospace with the full value preserved', () => {
    const did = 'did:web:demo.example.com:departments:acme-signing-gateway';
    const [row] = buildReadableRows({ iss: did });
    expect(row.label).toBe('Issuer');
    expect(row.mono).toBe(true);
    expect(row.fullValue).toBe(did);
  });

  it('renders booleans as Yes/No and joins scalar arrays', () => {
    const rows = buildReadableRows({ ok: true, type: ['VerifiablePresentation', 'AgentVP'] });
    const byLabel = Object.fromEntries(rows.map(r => [r.label, r]));
    expect(byLabel['Ok'].value).toBe('Yes');
    expect(byLabel['Type'].value).toBe('VerifiablePresentation, AgentVP');
  });

  it('formats unix-second date claims and keeps the raw value', () => {
    const [row] = buildReadableRows({ exp: 1752000000 });
    expect(row.label).toBe('Expires');
    expect(row.fullValue).toBe('1752000000');
    expect(row.value).not.toBe('1752000000');
  });

  it('nests objects and arrays of objects as child rows', () => {
    const rows = buildReadableRows({
      verifiableCredential: [
        { credentialSubject: { workloadBinding: { policyDecisions: [{ scope: 'gateway' }] } } },
      ],
    });
    const creds = rows.find(r => r.label === 'Credentials');
    expect(creds?.children).toHaveLength(1);
    const first = creds!.children![0];
    expect(first.label).toBe('#1');
    const subject = first.children?.find(r => r.label === 'Subject claims');
    expect(subject?.children?.[0].label).toBe('Workload binding');
  });
});
