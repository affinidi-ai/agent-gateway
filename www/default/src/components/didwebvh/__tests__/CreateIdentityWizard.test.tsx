import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import CreateIdentityWizard from '../CreateIdentityWizard';
import { apiClient } from '../../../api';

// Mock the API client
jest.mock('../../../api', () => ({
  apiClient: {
    createDidWebVhIdentity: jest.fn(),
  },
}));

describe('CreateIdentityWizard', () => {
  const defaultProps = {
    show: true,
    onHide: jest.fn(),
    onSuccess: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    // Mock window.location.host for DID preview
    Object.defineProperty(window, 'location', {
      value: {
        host: 'example.com',
      },
      writable: true,
    });
  });

  it('renders step 1 initially', () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    expect(screen.getByText('Step 1: Basic Information')).toBeInTheDocument();
    expect(screen.getByLabelText(/Identity Name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/DID Path/i)).toBeInTheDocument();
  });

  it('shows DID preview when path is entered', async () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    const pathInput = screen.getByLabelText(/DID Path/i);
    fireEvent.change(pathInput, { target: { value: 'agents/test' } });

    await waitFor(() => {
      expect(screen.getByText(/did:webvh:example\.com:agents:test/i)).toBeInTheDocument();
    });
  });

  it('disables Next button when required fields are empty', () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    const nextButton = screen.getByText(/Next/i);
    expect(nextButton).toBeDisabled();
  });

  it('enables Next button when required fields are filled', async () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    fireEvent.change(screen.getByLabelText(/Identity Name/i), { target: { value: 'Test Agent' } });
    fireEvent.change(screen.getByLabelText(/DID Path/i), { target: { value: 'agents/test' } });

    await waitFor(() => {
      const nextButton = screen.getByText(/Next/i);
      expect(nextButton).not.toBeDisabled();
    });
  });

  it('navigates to step 2 when Next is clicked', async () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    fireEvent.change(screen.getByLabelText(/Identity Name/i), { target: { value: 'Test Agent' } });
    fireEvent.change(screen.getByLabelText(/DID Path/i), { target: { value: 'agents/test' } });

    const nextButton = screen.getByText(/Next/i);
    fireEvent.click(nextButton);

    await waitFor(() => {
      expect(screen.getByText('Step 2: Agent Configuration')).toBeInTheDocument();
    });
  });

  it('shows Previous button on step 2', async () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    // Fill step 1 and navigate
    fireEvent.change(screen.getByLabelText(/Identity Name/i), { target: { value: 'Test Agent' } });
    fireEvent.change(screen.getByLabelText(/DID Path/i), { target: { value: 'agents/test' } });
    fireEvent.click(screen.getByText(/Next/i));

    await waitFor(() => {
      expect(screen.getByText(/Previous/i)).toBeInTheDocument();
    });
  });

  it('navigates to step 3 when all required fields in step 2 are filled', async () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    // Step 1
    fireEvent.change(screen.getByLabelText(/Identity Name/i), { target: { value: 'Test Agent' } });
    fireEvent.change(screen.getByLabelText(/DID Path/i), { target: { value: 'agents/test' } });
    fireEvent.click(screen.getByText(/Next/i));

    // Step 2
    await waitFor(() => {
      expect(screen.getByText('Step 2: Agent Configuration')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/LLM Provider/i), { target: { value: 'OpenAI' } });
    fireEvent.change(screen.getByLabelText(/Model/i), { target: { value: 'GPT-4' } });
    fireEvent.click(screen.getAllByText(/Next/i)[0]);

    await waitFor(() => {
      expect(screen.getByText('Step 3: Metadata & Policies')).toBeInTheDocument();
    });
  });

  it('shows review configuration on step 3', async () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    // Navigate through all steps
    fireEvent.change(screen.getByLabelText(/Identity Name/i), { target: { value: 'Test Agent' } });
    fireEvent.change(screen.getByLabelText(/DID Path/i), { target: { value: 'agents/test' } });
    fireEvent.click(screen.getByText(/Next/i));

    await waitFor(() => {
      expect(screen.getByText('Step 2: Agent Configuration')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/LLM Provider/i), { target: { value: 'OpenAI' } });
    fireEvent.change(screen.getByLabelText(/Model/i), { target: { value: 'GPT-4' } });
    fireEvent.click(screen.getAllByText(/Next/i)[0]);

    await waitFor(() => {
      expect(screen.getByText(/Review Your Configuration/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/Test Agent/i)).toBeInTheDocument();
    expect(screen.getByText(/OpenAI\s+—\s+GPT-4/i)).toBeInTheDocument();
  });

  it('calls API and onSuccess when Create Identity is clicked', async () => {
    const mockIdentity = { id: 'new-id', did: 'did:webvh:example.com:agents:test' };
    (apiClient.createDidWebVhIdentity as jest.Mock).mockResolvedValue(mockIdentity);

    render(<CreateIdentityWizard {...defaultProps} />);

    // Fill all required fields
    fireEvent.change(screen.getByLabelText(/Identity Name/i), { target: { value: 'Test Agent' } });
    fireEvent.change(screen.getByLabelText(/DID Path/i), { target: { value: 'agents/test' } });
    fireEvent.click(screen.getByText(/Next/i));

    await waitFor(() => {
      expect(screen.getByText('Step 2: Agent Configuration')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/LLM Provider/i), { target: { value: 'OpenAI' } });
    fireEvent.change(screen.getByLabelText(/Model/i), { target: { value: 'GPT-4' } });
    fireEvent.click(screen.getAllByText(/Next/i)[0]);

    await waitFor(() => {
      expect(screen.getByText('Step 3: Metadata & Policies')).toBeInTheDocument();
    });

    const createButton = screen.getByText(/Create Identity/i);
    fireEvent.click(createButton);

    await waitFor(() => {
      expect(apiClient.createDidWebVhIdentity).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Test Agent',
          did_path: 'agents/test',
        })
      );
    });
    await waitFor(() => {
      expect(defaultProps.onSuccess).toHaveBeenCalledWith(mockIdentity);
    });
  });

  it('shows error message when API call fails', async () => {
    const errorMessage = 'Failed to create identity';
    (apiClient.createDidWebVhIdentity as jest.Mock).mockRejectedValue(new Error(errorMessage));

    render(<CreateIdentityWizard {...defaultProps} />);

    // Navigate to final step
    fireEvent.change(screen.getByLabelText(/Identity Name/i), { target: { value: 'Test Agent' } });
    fireEvent.change(screen.getByLabelText(/DID Path/i), { target: { value: 'agents/test' } });
    fireEvent.click(screen.getByText(/Next/i));

    await waitFor(() => {
      expect(screen.getByText('Step 2: Agent Configuration')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/LLM Provider/i), { target: { value: 'OpenAI' } });
    fireEvent.change(screen.getByLabelText(/Model/i), { target: { value: 'GPT-4' } });
    fireEvent.click(screen.getAllByText(/Next/i)[0]);

    await waitFor(() => {
      expect(screen.getByText('Step 3: Metadata & Policies')).toBeInTheDocument();
    });

    const createButton = screen.getByText(/Create Identity/i);
    fireEvent.click(createButton);

    await waitFor(() => {
      expect(screen.getByText(errorMessage)).toBeInTheDocument();
    });
  });

  it('closes modal when Cancel is clicked', () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    const cancelButton = screen.getByText('Cancel');
    fireEvent.click(cancelButton);

    expect(defaultProps.onHide).toHaveBeenCalledTimes(1);
  });

  it('toggles capabilities checkboxes', async () => {
    render(<CreateIdentityWizard {...defaultProps} />);

    // Navigate to step 2
    fireEvent.change(screen.getByLabelText(/Identity Name/i), { target: { value: 'Test Agent' } });
    fireEvent.change(screen.getByLabelText(/DID Path/i), { target: { value: 'agents/test' } });
    fireEvent.click(screen.getByText(/Next/i));

    await waitFor(() => {
      expect(screen.getByText('Step 2: Agent Configuration')).toBeInTheDocument();
    });

    const reasoningCheckbox = screen.getByLabelText(/Reasoning/i);
    const codeCheckbox = screen.getByLabelText(/Code Generation/i);

    fireEvent.click(reasoningCheckbox);
    fireEvent.click(codeCheckbox);

    expect(reasoningCheckbox).toBeChecked();
    expect(codeCheckbox).toBeChecked();
  });
});
