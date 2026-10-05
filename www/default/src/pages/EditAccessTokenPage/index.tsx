import React, { useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { usePageTitle } from '../../context/PageTitleContext';
import { usePermissions } from '../../context/PermissionsContext';
import AccessTokenCreatedView from './AccessTokenCreatedView';
import AccessTokenEditHeader from './AccessTokenEditHeader';
import AccessTokenFormCard from './AccessTokenFormCard';
import AccessTokenSidebar from './AccessTokenSidebar';
import { useAccessTokenEditor } from './useAccessTokenEditor';

const EditAccessTokenPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { permissions, hasPermission } = usePermissions();
  const availableScopes = Object.entries(permissions ?? {})
    .filter(([, allowed]) => allowed)
    .map(([scope]) => scope);
  const editor = useAccessTokenEditor(id, availableScopes);

  usePageTitle(editor.isEditMode ? 'Edit Access Token' : 'New Access Token');

  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 's' && !event.repeat) {
        event.preventDefault();
        if (!editor.loading && !editor.created && !editor.saving && !editor.revoked) {
          void editor.save();
        }
      }
    };

    window.addEventListener('keydown', handleKeyboardSave);
    return () => window.removeEventListener('keydown', handleKeyboardSave);
  }, [editor]);

  if (editor.loading) {
    return (
      <div className="container-fluid text-center py-5" data-testid="access-token-loading">
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  if (editor.created) {
    return <AccessTokenCreatedView token={editor.created} onDone={editor.leave} />;
  }

  return (
    <div className="container-fluid" data-testid="page-access-token">
      <AccessTokenEditHeader
        title={editor.isEditMode ? 'Edit Access Token' : 'Create Access Token'}
        subtitle={
          editor.isEditMode
            ? 'Update the token identity, scopes, and resource boundary.'
            : 'Mint a management API credential with an explicit scope boundary.'
        }
        saving={editor.saving}
        saveDisabled={editor.saving || editor.revoked}
        onBack={editor.leave}
        onSave={() => void editor.save()}
      />
      <div className="row">
        <div className="col-lg-8">
          <AccessTokenFormCard
            editor={editor}
            availableScopes={availableScopes}
            canRevoke={hasPermission('access_tokens.delete')}
          />
        </div>
        <div className="col-lg-4">
          <AccessTokenSidebar meta={editor.token} />
        </div>
      </div>
    </div>
  );
};

export default EditAccessTokenPage;
