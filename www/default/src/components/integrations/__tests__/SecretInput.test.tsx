import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import SecretInput from '../SecretInput';
import { SecretEdit } from '../../../pages/EndpointEditorPage/endpointFields';

function Harness({
  initial,
  stored,
  required = false,
  multiline = false,
  secretOptions,
}: {
  initial: SecretEdit;
  stored: boolean;
  required?: boolean;
  multiline?: boolean;
  secretOptions?: { id: string; name: string }[];
}) {
  const [edit, setEdit] = useState<SecretEdit>(initial);
  return (
    <>
      <SecretInput
        id="smtp_password"
        label="SMTP password"
        edit={edit}
        stored={stored}
        required={required}
        multiline={multiline}
        secretOptions={secretOptions}
        onChange={setEdit}
      />
      <output data-testid="edit">{JSON.stringify(edit)}</output>
    </>
  );
}

const edit = () => JSON.parse(screen.getByTestId('edit').textContent || '{}');

test('a stored secret is never shown and is kept by default', () => {
  render(<Harness initial={{ state: 'keep' }} stored />);

  expect(screen.getByText(/stored/i)).toBeInTheDocument();
  expect(screen.queryByLabelText('SMTP password')).not.toBeInTheDocument();
  expect(edit()).toEqual({ state: 'keep' });
});

test('replacing a stored secret takes a new value, and can go back to the stored one', () => {
  render(<Harness initial={{ state: 'keep' }} stored />);

  fireEvent.click(screen.getByRole('button', { name: /replace/i }));
  const input = screen.getByLabelText('SMTP password');
  expect(input).toHaveAttribute('type', 'password');
  fireEvent.change(input, { target: { value: 'hunter2' } });
  expect(edit()).toEqual({ state: 'set', value: 'hunter2' });

  fireEvent.click(screen.getByRole('button', { name: /keep stored value/i }));
  expect(edit()).toEqual({ state: 'keep' });
});

test('an optional stored secret can be cleared, and the clearing undone', () => {
  render(<Harness initial={{ state: 'keep' }} stored />);

  fireEvent.click(screen.getByRole('button', { name: /clear/i }));
  expect(edit()).toEqual({ state: 'clear' });
  expect(screen.getByText(/removed when you save/i)).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: /undo/i }));
  expect(edit()).toEqual({ state: 'keep' });
});

test('a required secret cannot be cleared', () => {
  render(<Harness initial={{ state: 'keep' }} stored required />);

  expect(screen.queryByRole('button', { name: /clear/i })).not.toBeInTheDocument();
});

test('without a stored value the field takes a value directly', () => {
  render(<Harness initial={{ state: 'set', value: '' }} stored={false} />);

  fireEvent.change(screen.getByLabelText('SMTP password'), { target: { value: 'pw' } });

  expect(edit()).toEqual({ state: 'set', value: 'pw' });
  expect(screen.queryByRole('button', { name: /keep stored value/i })).not.toBeInTheDocument();
});

test('a secret reference is shown, since it holds no secret', () => {
  render(<Harness initial={{ state: 'set', value: '$SECRET:smtp' }} stored={false} />);

  expect(screen.getByLabelText('SMTP password')).toHaveAttribute('type', 'text');
  expect(screen.getByText(/uses the stored secret smtp/i)).toBeInTheDocument();
});

test('a multi-line secret is a text area', () => {
  render(<Harness initial={{ state: 'set', value: '' }} stored={false} multiline />);

  expect(screen.getByLabelText('SMTP password').tagName).toBe('TEXTAREA');
});

const SECRETS = [
  { id: 'smtp', name: 'SMTP password' },
  { id: 'relay', name: 'Relay password' },
];

test('a stored secret can be picked instead of typing a value', () => {
  render(<Harness initial={{ state: 'set', value: '' }} stored={false} secretOptions={SECRETS} />);

  fireEvent.change(screen.getByLabelText(/use a stored secret/i), { target: { value: 'relay' } });

  expect(edit()).toEqual({ state: 'set', value: '$SECRET:relay' });
  expect(screen.getByText(/uses the stored secret relay password/i)).toBeInTheDocument();
});

test('picking no stored secret goes back to typing a value', () => {
  render(
    <Harness
      initial={{ state: 'set', value: '$SECRET:smtp' }}
      stored={false}
      secretOptions={SECRETS}
    />
  );
  const picker = screen.getByLabelText(/use a stored secret/i);
  expect(picker).toHaveValue('smtp');

  fireEvent.change(picker, { target: { value: '' } });

  expect(edit()).toEqual({ state: 'set', value: '' });
  expect(screen.getByLabelText('SMTP password')).toHaveAttribute('type', 'password');
});

test('a reference to a secret that is not listed stays selectable', () => {
  render(
    <Harness
      initial={{ state: 'set', value: '$SECRET:retired' }}
      stored={false}
      secretOptions={SECRETS}
    />
  );

  expect(screen.getByLabelText(/use a stored secret/i)).toHaveValue('retired');
  expect(screen.getByRole('option', { name: 'retired (not listed)' })).toBeInTheDocument();
});

test('without secret options there is no picker', () => {
  render(<Harness initial={{ state: 'set', value: '' }} stored={false} />);

  expect(screen.queryByLabelText(/use a stored secret/i)).not.toBeInTheDocument();
});
