import React, { useEffect, useState } from 'react';
import { apiClient } from '../api';
import { formatDateTime } from '../utils/stringUtils';
import { DeleteButton } from '../components/shared/DeleteButton';
import { usePermissions } from '../context/PermissionsContext';

interface Notification {
  id: string;
  title: string;
  message: string;
  notification_type: 'general' | 'gateway-connection-request' | 'system';
  metadata: {
    username?: string;
    user_id?: string;
    action?: string;
  };
  status: 'new' | 'read' | 'deleted';
  created_at: string;
  updated_at: string;
}

const NotificationsPage: React.FC = () => {
  const { hasPermission } = usePermissions();
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [selectedNotification, setSelectedNotification] = useState<Notification | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [actionInProgress, setActionInProgress] = useState(false);

  useEffect(() => {
    fetchNotifications();
  }, []);

  const fetchNotifications = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/notifications');
      setNotifications(response.data);
    } catch (error: any) {
      setError(error.message || 'Failed to load notifications');
    } finally {
      setLoading(false);
    }
  };

  const handleNotificationClick = (notification: Notification) => {
    setSelectedNotification(notification);
    setShowModal(true);
  };

  const handleCloseModal = () => {
    setShowModal(false);
    setSelectedNotification(null);
  };

  const handleMarkAsRead = async (id: string) => {
    try {
      await apiClient.put(`/notifications/${id}`, { status: 'read' });
      handleCloseModal();
      fetchNotifications();
    } catch (error: any) {
      setError(error.message || 'Failed to mark notification as read');
    }
  };

  const handleDelete = async (id: string, e?: React.MouseEvent) => {
    // Stop propagation to prevent opening the modal when clicking delete in the table
    if (e) {
      e.stopPropagation();
    }

    try {
      await apiClient.delete(`/notifications/${id}`);
      setSuccess('Notification deleted successfully');
      setTimeout(() => setSuccess(null), 3000);
      handleCloseModal();
      fetchNotifications();
    } catch (error: any) {
      setError(error.message || 'Failed to delete notification');
    }
  };

  const isUserApprovalNotification = (notification: Notification): boolean => {
    return (
      notification.notification_type === 'system' &&
      notification.metadata?.action === 'user_approval' &&
      !!notification.metadata?.user_id
    );
  };

  const handleApproveUser = async (notification: Notification) => {
    const userId = notification.metadata?.user_id;
    if (!userId) return;

    try {
      setActionInProgress(true);
      await apiClient.put(`/users/${userId}`, { status: 'approved' });
      setSuccess(`User '${notification.metadata?.username || userId}' approved successfully`);
      setTimeout(() => setSuccess(null), 3000);
      await handleMarkAsRead(notification.id);
    } catch (error: any) {
      setError(error.message || 'Failed to approve user');
    } finally {
      setActionInProgress(false);
    }
  };

  const handleRejectUser = async (notification: Notification) => {
    const userId = notification.metadata?.user_id;
    if (!userId) return;

    if (
      !window.confirm(
        `Are you sure you want to reject and delete user '${notification.metadata?.username || userId}'? This action cannot be undone.`
      )
    ) {
      return;
    }

    try {
      setActionInProgress(true);
      await apiClient.delete(`/users/${userId}`);
      setSuccess(`User '${notification.metadata?.username || userId}' rejected and deleted`);
      setTimeout(() => setSuccess(null), 3000);
      await handleMarkAsRead(notification.id);
    } catch (error: any) {
      setError(error.message || 'Failed to reject user');
    } finally {
      setActionInProgress(false);
    }
  };

  const formatDate = (dateString: string) => {
    return formatDateTime(dateString, true);
  };

  return (
    <div className="container-fluid">
      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}
      {success && (
        <div className="alert alert-success alert-dismissible fade show" role="alert">
          {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            aria-label="Close"
          />
        </div>
      )}

      {loading ? (
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '60vh',
          }}
        >
          <div className="spinner-border" role="status" style={{ color: 'rgba(0, 0, 0, 0.5)' }}>
            <span className="visually-hidden"></span>
          </div>
        </div>
      ) : notifications.length === 0 ? (
        <div className="card shadow mb-4">
          <div className="card-body text-center">
            <div className="text-muted">
              <i className="fas fa-bell fa-3x mb-3"></i>
              <p>No notifications found.</p>
            </div>
          </div>
        </div>
      ) : (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-bell"></i> All Notifications
            </h6>
          </div>
          <div className="card-body">
            <div className="table-responsive">
              <table className="table table-hover table-sm">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Message</th>
                    <th>Created</th>
                    <th>Status</th>
                    <th style={{ width: '80px' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {notifications.map(notification => (
                    <tr
                      key={notification.id}
                      className={notification.status === 'new' ? 'table-light fw-bold' : ''}
                    >
                      <td
                        onClick={() => handleNotificationClick(notification)}
                        style={{ cursor: 'pointer' }}
                      >
                        {notification.title}
                      </td>
                      <td
                        onClick={() => handleNotificationClick(notification)}
                        style={{ cursor: 'pointer' }}
                      >
                        <small>
                          {notification.message.substring(0, 300)}
                          {notification.message.length > 300 ? '...' : ''}
                        </small>
                      </td>
                      <td
                        onClick={() => handleNotificationClick(notification)}
                        style={{ cursor: 'pointer' }}
                      >
                        <small>{formatDate(notification.created_at)}</small>
                      </td>
                      <td
                        onClick={() => handleNotificationClick(notification)}
                        style={{ cursor: 'pointer' }}
                      >
                        <span
                          className={`badge ${
                            notification.status === 'new'
                              ? 'bg-primary text-white'
                              : notification.status === 'read'
                                ? 'bg-secondary text-white'
                                : 'bg-danger text-white'
                          }`}
                        >
                          {notification.status.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <DeleteButton
                          onDelete={() => handleDelete(notification.id)}
                          className="btn-sm"
                          title="Delete notification"
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Notification Detail Modal */}
      {showModal && selectedNotification && (
        <>
          <div className="modal show d-block" tabIndex={-1} role="dialog">
            <div className="modal-dialog modal-lg" role="document">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">
                    <i className="fas fa-bell me-2"></i>
                    {selectedNotification.title}
                  </h5>
                  <button
                    type="button"
                    className="btn-close"
                    onClick={handleCloseModal}
                    aria-label="Close"
                  />
                </div>
                <div className="modal-body">
                  <div className="mb-3">
                    <label className="form-label fw-bold">Message:</label>
                    <p className="border rounded p-3 bg-light">{selectedNotification.message}</p>
                  </div>

                  {/* Approve/reject actions from the modal for new user notifications */}
                  {isUserApprovalNotification(selectedNotification) &&
                    selectedNotification.status === 'new' &&
                    hasPermission('users.approve') && (
                      <div className="d-flex align-items-center justify-content-between border rounded p-3 mb-3 bg-light">
                        <span className="text-muted">
                          Approve or reject user '{selectedNotification.metadata?.username}'
                          directly from this notification.
                        </span>
                        <div className="d-flex align-items-center" style={{ gap: '0.5rem' }}>
                          <button
                            className="btn btn-sm btn-success"
                            onClick={() => handleApproveUser(selectedNotification)}
                            disabled={actionInProgress}
                            title="Quick approve user"
                          >
                            {actionInProgress ? (
                              <i className="fas fa-spinner fa-spin"></i>
                            ) : (
                              'Approve'
                            )}
                          </button>
                          <button
                            className="btn btn-sm btn-outline-danger"
                            onClick={() => handleRejectUser(selectedNotification)}
                            disabled={actionInProgress}
                            title="Reject user"
                          >
                            {actionInProgress ? (
                              <i className="fas fa-spinner fa-spin"></i>
                            ) : (
                              'Reject'
                            )}
                          </button>
                        </div>
                      </div>
                    )}

                  <div className="row">
                    <div className="col-md-6">
                      <label className="form-label fw-bold">Status:</label>
                      <p>
                        <span
                          className={`badge ${
                            selectedNotification.status === 'new'
                              ? 'bg-primary text-white'
                              : selectedNotification.status === 'read'
                                ? 'bg-secondary text-white'
                                : 'bg-danger text-white'
                          }`}
                        >
                          {selectedNotification.status.toUpperCase()}
                        </span>
                      </p>
                    </div>
                    <div className="col-md-6">
                      <label className="form-label fw-bold">Created:</label>
                      <p>{formatDate(selectedNotification.created_at)}</p>
                    </div>
                  </div>
                  {selectedNotification.updated_at !== selectedNotification.created_at && (
                    <div className="mt-2">
                      <label className="form-label fw-bold">Updated:</label>
                      <p>{formatDate(selectedNotification.updated_at)}</p>
                    </div>
                  )}
                </div>
                <div className="modal-footer">
                  {selectedNotification.status === 'new' && (
                    <button
                      className="btn btn-success"
                      onClick={() => handleMarkAsRead(selectedNotification.id)}
                    >
                      <i className="fas fa-check me-2"></i> Mark as Read
                    </button>
                  )}
                  <DeleteButton
                    onDelete={() => handleDelete(selectedNotification.id)}
                    variant="danger"
                  >
                    Delete
                  </DeleteButton>
                  <button className="btn btn-secondary" onClick={handleCloseModal}>
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
          <div className="modal-backdrop show"></div>
        </>
      )}
    </div>
  );
};

export default NotificationsPage;
