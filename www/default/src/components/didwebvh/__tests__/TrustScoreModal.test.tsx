import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import TrustScoreModal from '../TrustScoreModal';
import { apiClient } from '../../../api';

// Mock the API client
jest.mock('../../../api', () => ({
  apiClient: {
    getIdentityTrustScore: jest.fn(),
  },
}));

// Mock chart.js to avoid rendering issues in tests
jest.mock('react-chartjs-2', () => ({
  Radar: () => <div data-testid="radar-chart" />,
}));

jest.mock('chart.js', () => ({
  Chart: {
    register: jest.fn(),
  },
  RadialLinearScale: jest.fn(),
  PointElement: jest.fn(),
  LineElement: jest.fn(),
  Filler: jest.fn(),
  Tooltip: jest.fn(),
  Legend: jest.fn(),
}));

const mockTrustScore = {
  did: 'did:webvh:example.com:agents:test',
  overall_score: 0.85,
  components: {
    genesis: 0.92,
    behavioral: 0.78,
    operational: 0.85,
    attestation: 0.82,
    history: 0.9,
  },
  computed_at: '2026-02-13T10:00:00Z',
  version: 3,
  has_tee: true,
  has_cloud_attestation: false,
};

describe('TrustScoreModal', () => {
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
    (apiClient.getIdentityTrustScore as jest.Mock).mockImplementation(
      () => new Promise(() => {}) // Never resolves to keep loading state
    );

    render(<TrustScoreModal {...defaultProps} />);

    expect(screen.getByText(/Loading trust score/i)).toBeInTheDocument();
  });

  it('loads and displays trust score data', async () => {
    (apiClient.getIdentityTrustScore as jest.Mock).mockResolvedValue(mockTrustScore);

    render(<TrustScoreModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('85%')).toBeInTheDocument();
    });
    expect(screen.getByText('TRUSTED')).toBeInTheDocument();

    // Check component scores are displayed (using getAllByText since they appear multiple times)
    expect(screen.getAllByText(/Genesis/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Behavioral/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Operational/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Attestation/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/History/i).length).toBeGreaterThan(0);
  });

  it('displays error message on API failure', async () => {
    const errorMessage = 'Failed to load trust score';
    (apiClient.getIdentityTrustScore as jest.Mock).mockRejectedValue(new Error(errorMessage));

    render(<TrustScoreModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText(errorMessage)).toBeInTheDocument();
    });
  });

  it('calls onHide when close button is clicked', async () => {
    (apiClient.getIdentityTrustScore as jest.Mock).mockResolvedValue(mockTrustScore);

    render(<TrustScoreModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('85%')).toBeInTheDocument();
    });

    const closeButton = screen.getByText('Close');
    fireEvent.click(closeButton);

    expect(defaultProps.onHide).toHaveBeenCalledTimes(1);
  });

  it('refreshes trust score when refresh button is clicked', async () => {
    (apiClient.getIdentityTrustScore as jest.Mock).mockResolvedValue(mockTrustScore);

    render(<TrustScoreModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('85%')).toBeInTheDocument();
    });

    const refreshButton = screen.getByText('Refresh');
    fireEvent.click(refreshButton);

    await waitFor(() => {
      expect(apiClient.getIdentityTrustScore).toHaveBeenCalledTimes(2);
    });
  });

  it('does not load data when modal is not shown', () => {
    render(<TrustScoreModal {...defaultProps} show={false} />);

    expect(apiClient.getIdentityTrustScore).not.toHaveBeenCalled();
  });

  it('displays weighted calculation correctly', async () => {
    (apiClient.getIdentityTrustScore as jest.Mock).mockResolvedValue(mockTrustScore);

    render(<TrustScoreModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText(/Genesis \(25%\):/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/Behavioral \(25%\):/i)).toBeInTheDocument();
    expect(screen.getByText(/Operational \(20%\):/i)).toBeInTheDocument();
    expect(screen.getByText(/Attestation \(20%\):/i)).toBeInTheDocument();
    expect(screen.getByText(/History \(10%\):/i)).toBeInTheDocument();
  });

  it('shows correct trust score label for high score', async () => {
    (apiClient.getIdentityTrustScore as jest.Mock).mockResolvedValue({
      ...mockTrustScore,
      overall_score: 0.95,
    });

    render(<TrustScoreModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('TRUSTED')).toBeInTheDocument();
    });
  });

  it('shows correct trust score label for low score', async () => {
    (apiClient.getIdentityTrustScore as jest.Mock).mockResolvedValue({
      ...mockTrustScore,
      overall_score: 0.35,
    });

    render(<TrustScoreModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText('LOW TRUST')).toBeInTheDocument();
    });
  });

  it('displays TEE and cloud attestation status', async () => {
    (apiClient.getIdentityTrustScore as jest.Mock).mockResolvedValue(mockTrustScore);

    render(<TrustScoreModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByText(/TEE attestation:/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/Cloud attestation:/i)).toBeInTheDocument();
  });

  it('renders radar chart component', async () => {
    (apiClient.getIdentityTrustScore as jest.Mock).mockResolvedValue(mockTrustScore);

    render(<TrustScoreModal {...defaultProps} />);

    await waitFor(() => {
      expect(screen.getByTestId('radar-chart')).toBeInTheDocument();
    });
  });
});
