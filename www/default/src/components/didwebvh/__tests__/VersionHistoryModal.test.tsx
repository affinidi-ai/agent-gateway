import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import VersionHistoryModal from '../VersionHistoryModal';
import { apiClient } from '../../../api';

// Mock the API client
jest.mock('../../../api', () => ({
  apiClient: {
    getIdentityVersionHistory: jest.fn(),
    verifyDidWebVh: jest.fn(),
  },
}));

// Mock utils
jest.mock('../../../utils/stringUtils', () => ({
  formatDateTime: jest.fn(date => `Formatted: ${date}`),
}));

const mockVersionHistory = [
  {
    version: 3,
    timestamp: '2026-02-13T10:00:00Z',
    operation: 'update',
    signer: 'did:web:example.com:admin',
    hash: 'abc123def456',
    changes: ['Updated metadata', 'Modified capabilities'],
    metadata: { reason: 'Version 3 update' },
  },
  {
    version: 2,
    timestamp: '2026-02-10T10:00:00Z',
    operation: 'key_rotation',
    signer: 'did:web:example.com:admin',
    hash: 'def456ghi789',
    changes: ['Rotated signing key'],
    metadata: { key_id: 'key-xyz' },
  },
  {
    version: 1,
    timestamp: '2026-02-01T10:00:00Z',
    operation: 'birth',
    signer: 'did:web:example.com:admin',
    hash: 'ghi789jkl012',
    changes: ['Initial creation'],
    metadata: { genesis: true },
  },
];

describe('VersionHistoryModal', () => {
  const defaultProps = {
    identityId: 'test-id-123',
    did: 'did:webvh:example.com:agents:test',
    show: true,
    onHide: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders loading state initially', () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockImplementation(
      () => new Promise(() => {}) // Never resolves to keep loading state
    );

    render(<VersionHistoryModal {...defaultProps} />);

    expect(screen.getByText(/Loading version history/i)).toBeInTheDocument();
  });

  it('loads and displays version history', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mockVersionHistory,
    });

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('v3')).toBeInTheDocument();
    });
    expect(screen.getByText('v2')).toBeInTheDocument();
    expect(screen.getByText('v1')).toBeInTheDocument();

    // Check operation badges
    expect(screen.getByText('UPDATE')).toBeInTheDocument();
    expect(screen.getByText('KEY ROTATION')).toBeInTheDocument();
    expect(screen.getByText('GENESIS')).toBeInTheDocument();
  });

  it('displays error message on API failure', async () => {
    const errorMessage = 'Failed to load version history';
    (apiClient.getIdentityVersionHistory as jest.Mock).mockRejectedValue(new Error(errorMessage));

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(errorMessage);
    });
  });

  it('shows CURRENT badge for latest version', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mockVersionHistory,
    });

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      const currentBadges = screen.getAllByText('CURRENT');
      expect(currentBadges.length).toBeGreaterThan(0);
    });
  });

  it('displays version details correctly', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mockVersionHistory,
    });

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getAllByText('did:web:example.com:admin').length).toBeGreaterThan(0);
    });
    expect(screen.getByText('abc123def456')).toBeInTheDocument();
    expect(screen.getByText('Updated metadata')).toBeInTheDocument();
    expect(screen.getByText('Modified capabilities')).toBeInTheDocument();
  });

  it('toggles version comparison UI', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mockVersionHistory,
    });

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('v3')).toBeInTheDocument();
    });

    // Version comparison should be visible
    expect(screen.getByText('Version Comparison')).toBeInTheDocument();

    const v1Select = screen.getAllByRole('combobox')[0];
    const v2Select = screen.getAllByRole('combobox')[1];

    expect(v1Select).toBeInTheDocument();
    expect(v2Select).toBeInTheDocument();
  });

  it('runs version comparison when button clicked', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mockVersionHistory,
    });

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('v3')).toBeInTheDocument();
    });

    const compareButton = screen.getByText('Run Comparison');
    fireEvent.click(compareButton);

    await waitFor(
      () => {
        // Should show some comparison result
        expect(screen.getByText(/Comparing/i)).toBeInTheDocument();
      },
      { timeout: 2000 }
    );
  });

  it('verifies chain integrity when Verify button clicked', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mockVersionHistory,
    });
    (apiClient.verifyDidWebVh as jest.Mock).mockResolvedValue({
      valid: true,
      checks: {
        genesis_scid_valid: true,
        version_chain_intact: true,
        signatures_verified: true,
        no_tampering: true,
        hash_chain_continuous: true,
      },
    });

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('v3')).toBeInTheDocument();
    });

    const verifyButton = screen.getByText('Verify Chain');
    fireEvent.click(verifyButton);

    await waitFor(() => {
      expect(apiClient.verifyDidWebVh).toHaveBeenCalledWith(defaultProps.did);
    });
    await waitFor(() => {
      expect(screen.getByText('DID Log Integrity Verified')).toBeInTheDocument();
    });
  });

  it('shows verification error when verification fails', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mockVersionHistory,
    });
    const errorMessage = 'Verification failed';
    (apiClient.verifyDidWebVh as jest.Mock).mockRejectedValue(new Error(errorMessage));

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('v3')).toBeInTheDocument();
    });

    const verifyButton = screen.getByText('Verify Chain');
    fireEvent.click(verifyButton);

    await waitFor(() => {
      expect(screen.getByText(errorMessage)).toBeInTheDocument();
    });
  });

  it('calls onHide when close button is clicked', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mockVersionHistory,
    });

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('v3')).toBeInTheDocument();
    });

    const closeButton = screen.getByText('Close');
    fireEvent.click(closeButton);

    expect(defaultProps.onHide).toHaveBeenCalledTimes(1);
  });

  it('does not load data when modal is not shown', () => {
    render(<VersionHistoryModal {...defaultProps} show={false} />);

    expect(apiClient.getIdentityVersionHistory).not.toHaveBeenCalled();
  });

  it('displays different operation badges with correct styles', async () => {
    const mixedHistory = [
      { ...mockVersionHistory[0], operation: 'update' },
      { ...mockVersionHistory[1], operation: 'key_rotation' },
      { ...mockVersionHistory[2], operation: 'transfer' },
    ];
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mixedHistory,
    });

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('UPDATE')).toBeInTheDocument();
    });
    expect(screen.getByText('KEY ROTATION')).toBeInTheDocument();
    expect(screen.getByText('TRANSFER')).toBeInTheDocument();
  });

  it('expands and collapses metadata sections', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue({
      versions: mockVersionHistory,
    });

    render(<VersionHistoryModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('v3')).toBeInTheDocument();
    });

    const metadataToggles = screen.getAllByText('View metadata');
    expect(metadataToggles.length).toBeGreaterThan(0);

    // Click to expand
    fireEvent.click(metadataToggles[0]);

    // Should show metadata content
    await waitFor(() => {
      expect(screen.getByText(/"reason"/)).toBeInTheDocument();
    });
  });
});
