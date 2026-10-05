import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import PolicyConfigModal from '../PolicyConfigModal';

describe('PolicyConfigModal', () => {
  const mockIdentity = {
    uuid: 'test-uuid-123',
    name: 'Test Agent',
    did: 'did:webvh:example.com:test-agent',
    trust_score: {
      overall_score: 0.85,
      components: {
        genesis: 0.92,
        behavioral: 0.78,
        operational: 0.85,
        attestation: 0.8,
        history: 0.75,
      },
      has_tee: true,
    },
  };

  const mockOnHide = jest.fn();
  const mockOnSave = jest.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    jest.clearAllMocks();
    (global as any).fetch = jest
      .fn()
      .mockResolvedValue({ ok: false, status: 404, statusText: 'Not Found' });
    mockOnSave.mockResolvedValue(undefined);
  });

  it('renders modal with title and identity name', () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    expect(screen.getByText('Policy Configuration')).toBeInTheDocument();
    expect(screen.getByText('(Test Agent)')).toBeInTheDocument();
  });

  it('displays policy template buttons', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Standard/i })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /High Security/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Development/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Production/i })).toBeInTheDocument();
  });

  it('applies template when template button is clicked', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    const highSecButton = await screen.findByRole('button', { name: /High Security/i });
    fireEvent.click(highSecButton);

    // Should show modified indicator
    await waitFor(() => {
      expect(screen.getByText(/You have unsaved changes/i)).toBeInTheDocument();
    });

    // High Security template has minTrustScore of 0.85 (85%)
    const overallScoreBadge = screen.getAllByText('85%')[0];
    expect(overallScoreBadge).toBeInTheDocument();
  });

  it('shows all component threshold sliders', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Genesis Score')).toBeInTheDocument();
    });
    expect(screen.getByText('Behavioral Score')).toBeInTheDocument();
    expect(screen.getByText('Operational Score')).toBeInTheDocument();
    expect(screen.getByText('Attestation Score')).toBeInTheDocument();
    expect(screen.getByText('History Score')).toBeInTheDocument();
  });

  it('shows component weight badges', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    await waitFor(() => {
      // Check that weight badges exist (multiple components can have same weight)
      const weight025 = screen.getAllByText('weight: 0.25');
      expect(weight025).toHaveLength(2); // Genesis and Behavioral
    });

    const weight02 = screen.getAllByText('weight: 0.2');
    expect(weight02).toHaveLength(2); // Operational and Attestation
    expect(screen.getByText('weight: 0.1')).toBeInTheDocument(); // History
  });

  it('shows required checkboxes for each component', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    await waitFor(() => {
      const requiredText = screen.getAllByText('Required');
      expect(requiredText.length).toBeGreaterThanOrEqual(5); // At least 5 components
    });
  });

  it('shows TEE and Cloud checkboxes for operational component', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('TEE Required')).toBeInTheDocument();
    });
    expect(screen.getByText('Cloud Required')).toBeInTheDocument();
  });

  it('shows attestation count input', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Minimum attestation count')).toBeInTheDocument();
    });
  });

  it('has collapsible advanced section for OPA/Rego policy', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /Advanced: OPA\/Rego Policy/i })
      ).toBeInTheDocument();
    });
  });

  it('runs policy test when Test Policy button is clicked', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    const testButton = await screen.findByRole('button', { name: /Test Policy/i });
    await waitFor(() => expect(testButton).not.toBeDisabled());
    fireEvent.click(testButton);

    await waitFor(() => {
      expect(screen.getByText('ALLOWED')).toBeInTheDocument();
    });

    // Should show test result details
    expect(screen.getByText(/Overall score/i)).toBeInTheDocument();
  });

  it('calls onSave when Save button is clicked', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    // Make a change to enable Save button
    const highSecButton = await screen.findByRole('button', { name: /High Security/i });
    fireEvent.click(highSecButton);

    await waitFor(() => {
      expect(screen.getByText(/You have unsaved changes/i)).toBeInTheDocument();
    });

    const saveButton = screen.getByRole('button', { name: /^Save$/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(mockOnSave).toHaveBeenCalledTimes(1);
    });
  });

  it('calls onHide when Cancel button is clicked', () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    const cancelButton = screen.getByRole('button', { name: /Cancel/i });
    fireEvent.click(cancelButton);

    expect(mockOnHide).toHaveBeenCalledTimes(1);
  });

  it('disables Save button when no changes made', () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    const saveButton = screen.getByRole('button', { name: /^Save$/i });
    expect(saveButton).toBeDisabled();
  });

  it('enables Save button when changes are made', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    // Apply a template to make changes
    const devButton = await screen.findByRole('button', { name: /Development/i });
    fireEvent.click(devButton);

    await waitFor(() => {
      const saveButton = screen.getByRole('button', { name: /^Save$/i });
      expect(saveButton).not.toBeDisabled();
    });
  });

  it('shows Test & Save button', () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    expect(screen.getByRole('button', { name: /Test & Save/i })).toBeInTheDocument();
  });

  it('marks Standard template as selected by default', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    const standardButton = await screen.findByRole('button', { name: /Standard/i });
    expect(standardButton).toHaveClass('btn-primary');
  });

  it('changes to Custom when user modifies a value', async () => {
    render(
      <PolicyConfigModal
        show={true}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    // Click Standard template first
    const standardButton = await screen.findByRole('button', { name: /Standard/i });
    fireEvent.click(standardButton);

    // Find a range slider and change its value
    const sliders = screen.getAllByRole('slider');
    fireEvent.change(sliders[0], { target: { value: '80' } });

    // Should show Custom badge
    await waitFor(() => {
      expect(screen.getByText('Custom')).toBeInTheDocument();
    });
  });

  it('does not render when show is false', () => {
    render(
      <PolicyConfigModal
        show={false}
        onHide={mockOnHide}
        identity={mockIdentity}
        onSave={mockOnSave}
      />
    );

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
