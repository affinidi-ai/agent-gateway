import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import { UserAvatar } from '../components/shared/UserAvatar';
import { formatDateTime } from '../utils/stringUtils';
import { avatarImageSrc } from '../utils/avatar';

interface UserProfile {
  username: string;
  user_id: string;
  role: string;
  status: string;
  created_at: string;
  updated_at: string;
  first_name?: string;
  last_name?: string;
  email?: string;
  department?: string;
  job_title?: string;
  avatar_path?: string;
}

const MAX_AVATAR_SIZE = 5 * 1024 * 1024;

const ProfilePage: React.FC = () => {
  const navigate = useNavigate();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [form, setForm] = useState({
    first_name: '',
    last_name: '',
    email: '',
    department: '',
    job_title: '',
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  const [avatarPreview, setAvatarPreview] = useState<string>('');

  const fetchProfile = useCallback(async () => {
    try {
      setLoading(true);
      const response = await apiClient.get('/profile');
      setProfile(response.data);
      setForm({
        first_name: response.data.first_name || '',
        last_name: response.data.last_name || '',
        email: response.data.email || '',
        department: response.data.department || '',
        job_title: response.data.job_title || '',
      });
      setAvatarPreview('');
    } catch (err: any) {
      setError(err.message || 'Failed to load profile');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProfile();
  }, [fetchProfile]);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (saving) return;
      setError('');
      setSuccess('');
      try {
        setSaving(true);
        await apiClient.put('/profile', form);
        setSuccess('Profile updated successfully');
        setTimeout(() => setSuccess(''), 3000);
        fetchProfile();
      } catch (err: any) {
        setError(err.message || 'Failed to update profile');
      } finally {
        setSaving(false);
      }
    },
    [form, saving, fetchProfile]
  );

  // Keyboard shortcut Ctrl+S / Cmd+S
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        handleSubmit(event as any);
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleSubmit]);

  const handleAvatarChange = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;

      if (!file.type.startsWith('image/')) {
        setError('Please select an image file');
        return;
      }
      if (file.size > MAX_AVATAR_SIZE) {
        setError('Image size must be less than 5MB');
        return;
      }

      const reader = new FileReader();
      reader.onloadend = () => setAvatarPreview(reader.result as string);
      reader.readAsDataURL(file);

      setUploading(true);
      setError('');
      setSuccess('');

      try {
        const formData = new FormData();
        formData.append('avatar', file);
        const response = await apiClient.fetch('/api/v1/profile/avatar', {
          method: 'POST',
          body: formData,
        });
        if (!response.ok) throw new Error('Failed to upload avatar');
        setSuccess('Avatar uploaded successfully');
        setTimeout(() => setSuccess(''), 3000);
        fetchProfile();
      } catch (err: any) {
        setError(err.message || 'Failed to upload avatar');
        setAvatarPreview(avatarImageSrc(profile?.avatar_path) ?? '');
      } finally {
        setUploading(false);
      }
    },
    [profile, fetchProfile]
  );

  const handleGoBack = useCallback(() => navigate(-1), [navigate]);

  const handleFieldChange = useCallback(
    (field: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => {
      setForm(prev => ({ ...prev, [field]: e.target.value }));
    },
    []
  );

  if (loading) {
    return (
      <div className="container mt-4">
        <div className="text-center py-4">
          <div className="spinner-border" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={handleGoBack}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="row">
        <div className="col-lg-8 mx-auto">
          <div className="card shadow mb-4">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-user-circle"></i> My Profile
              </h6>
            </div>
            <div className="card-body">
              {error && (
                <div className="alert alert-danger" role="alert">
                  {error}
                </div>
              )}
              {success && (
                <div className="alert alert-success" role="alert">
                  {success}
                </div>
              )}

              {/* Avatar Section */}
              <div className="row mb-4">
                <div className="col-md-12 text-center">
                  <div className="mb-3">
                    <UserAvatar
                      avatarPath={profile?.avatar_path}
                      src={avatarPreview || undefined}
                      alt="Profile"
                      size="profile"
                    />
                  </div>
                  <div>
                    <label htmlFor="avatar-upload" className="btn btn-sm btn-primary">
                      <i className="fas fa-upload me-1"></i>
                      {uploading ? 'Uploading...' : 'Upload Avatar'}
                    </label>
                    <input
                      id="avatar-upload"
                      type="file"
                      accept="image/*"
                      onChange={handleAvatarChange}
                      disabled={uploading}
                      style={{ display: 'none' }}
                    />
                    <p className="text-muted small mt-2">
                      Max size: 5MB. Formats: JPG, PNG, GIF, WebP
                    </p>
                  </div>
                </div>
              </div>

              {/* Profile Form */}
              <form onSubmit={handleSubmit}>
                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label className="form-label">Username</label>
                    <input
                      type="text"
                      className="form-control"
                      value={profile?.username || ''}
                      disabled
                    />
                    <small className="text-muted">Username cannot be changed</small>
                  </div>
                  <div className="col-md-6 mb-3">
                    <label className="form-label">Role</label>
                    <input
                      type="text"
                      className="form-control"
                      value={profile?.role || ''}
                      disabled
                    />
                  </div>
                </div>

                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label className="form-label">First Name</label>
                    <input
                      type="text"
                      className="form-control"
                      value={form.first_name}
                      onChange={handleFieldChange('first_name')}
                      placeholder="Enter first name"
                    />
                  </div>
                  <div className="col-md-6 mb-3">
                    <label className="form-label">Last Name</label>
                    <input
                      type="text"
                      className="form-control"
                      value={form.last_name}
                      onChange={handleFieldChange('last_name')}
                      placeholder="Enter last name"
                    />
                  </div>
                </div>

                <div className="mb-3">
                  <label className="form-label">Email</label>
                  <input
                    type="email"
                    className="form-control"
                    value={form.email}
                    onChange={handleFieldChange('email')}
                    placeholder="Enter email address"
                  />
                </div>

                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label className="form-label">Created</label>
                    <input
                      type="text"
                      className="form-control"
                      value={profile?.created_at ? formatDateTime(profile.created_at, true) : ''}
                      disabled
                    />
                  </div>
                  <div className="col-md-6 mb-3">
                    <label className="form-label">Last Updated</label>
                    <input
                      type="text"
                      className="form-control"
                      value={profile?.updated_at ? formatDateTime(profile.updated_at, true) : ''}
                      disabled
                    />
                  </div>
                </div>

                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label className="form-label">Department</label>
                    <input
                      type="text"
                      className="form-control"
                      value={form.department}
                      onChange={handleFieldChange('department')}
                      placeholder="Enter department"
                    />
                  </div>
                  <div className="col-md-6 mb-3">
                    <label className="form-label">Job Title</label>
                    <input
                      type="text"
                      className="form-control"
                      value={form.job_title}
                      onChange={handleFieldChange('job_title')}
                      placeholder="Enter job title"
                    />
                  </div>
                </div>

                <div className="d-flex justify-content-end gap-2">
                  <button type="button" className="btn btn-secondary" onClick={handleGoBack}>
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={saving}>
                    {saving ? (
                      <>
                        <span
                          className="spinner-border spinner-border-sm me-2"
                          role="status"
                          aria-hidden="true"
                        ></span>
                        Saving...
                      </>
                    ) : (
                      <>
                        <i className="fas fa-save me-1"></i>
                        Save Changes
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;
