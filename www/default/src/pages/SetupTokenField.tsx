import React from 'react';
import { Form } from 'react-bootstrap';

interface SetupTokenFieldProps {
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
}

export const SetupTokenField: React.FC<SetupTokenFieldProps> = ({ value, onChange, disabled }) => (
  <Form.Group className="mb-3">
    <Form.Label htmlFor="setup-token">Setup token</Form.Label>
    <Form.Control
      id="setup-token"
      type="password"
      value={value}
      onChange={event => onChange(event.target.value)}
      placeholder="Paste the setup token"
      required
      disabled={disabled}
      autoComplete="one-time-code"
      maxLength={256}
      data-testid="login-setup-token"
      aria-describedby="setup-token-help"
    />
    <Form.Text id="setup-token-help">
      Needed for the first administrator only. It is in the setup-token file named in the gateway
      log.
    </Form.Text>
  </Form.Group>
);
