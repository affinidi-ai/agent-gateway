import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import GroupedEventPicker, { PickerEntry } from '../GroupedEventPicker';

const ENTRIES: PickerEntry[] = [
  {
    key: 'gateway.created',
    label: 'Gateway Created',
    description: 'A gateway was created',
    group: 'gateway',
    groupLabel: 'Gateway',
  },
  {
    key: 'gateway.deleted',
    label: 'Gateway Deleted',
    description: 'A gateway was deleted',
    group: 'gateway',
    groupLabel: 'Gateway',
  },
  {
    key: 'user.login',
    label: 'User Login',
    description: 'A user logged in',
    group: 'user',
    groupLabel: 'User',
  },
];

function Harness({ initial = [] as string[], entries = ENTRIES }) {
  const [selected, setSelected] = useState<string[]>(initial);
  return (
    <>
      <GroupedEventPicker
        entries={entries}
        selected={selected}
        onChange={setSelected}
        testIdPrefix="picker"
        searchable
      />
      <output data-testid="selected">{selected.join(',')}</output>
    </>
  );
}

const selected = () => screen.getByTestId('selected').textContent;
const search = (text: string) =>
  fireEvent.change(screen.getByRole('searchbox', { name: /search events/i }), {
    target: { value: text },
  });

test('lists entries under their groups', () => {
  render(<Harness />);

  expect(screen.getByTestId('picker-group-gateway')).toBeInTheDocument();
  expect(screen.getByTestId('picker-group-user')).toBeInTheDocument();
  expect(screen.getByLabelText(/gateway created/i)).toBeInTheDocument();
});

test('search narrows the list by name, id or description and hides empty groups', () => {
  render(<Harness />);

  search('logged in');
  expect(screen.getByLabelText(/user login/i)).toBeInTheDocument();
  expect(screen.queryByLabelText(/gateway created/i)).not.toBeInTheDocument();
  expect(screen.queryByTestId('picker-group-gateway')).not.toBeInTheDocument();

  search('gateway.deleted');
  expect(screen.getByLabelText(/gateway deleted/i)).toBeInTheDocument();
  expect(screen.queryByLabelText(/gateway created/i)).not.toBeInTheDocument();

  search('nothing like it');
  expect(screen.getByText(/no events match/i)).toBeInTheDocument();
});

test('a group toggle during a search changes only the events shown', () => {
  render(<Harness />);

  search('deleted');
  fireEvent.click(screen.getByTestId('picker-group-gateway'));

  expect(selected()).toBe('gateway.deleted');
});

test('the search keeps selections made outside it', () => {
  render(<Harness initial={['user.login']} />);

  search('gateway');
  fireEvent.click(screen.getByLabelText(/gateway created/i));

  expect(selected()).toBe('user.login,gateway.created');
});

test('says how many events are selected', () => {
  render(<Harness initial={['user.login', 'gateway.created']} />);

  expect(screen.getByText('2 of 3 events selected')).toBeInTheDocument();
});

test('a disabled entry cannot be toggled, alone or through its group', () => {
  const entries = ENTRIES.map(entry =>
    entry.key === 'gateway.deleted' ? { ...entry, disabled: true } : entry
  );
  render(<Harness entries={entries} initial={['gateway.deleted']} />);

  expect(screen.getByLabelText(/gateway deleted/i)).toBeDisabled();
  fireEvent.click(screen.getByTestId('picker-group-gateway'));

  expect(selected()).toBe('gateway.deleted,gateway.created');
});

test('a group of only disabled entries has a disabled toggle', () => {
  const entries = ENTRIES.map(entry =>
    entry.group === 'user' ? { ...entry, disabled: true } : entry
  );
  render(<Harness entries={entries} />);

  expect(screen.getByTestId('picker-group-user')).toBeDisabled();
  expect(screen.getByTestId('picker-group-gateway')).toBeEnabled();
});
