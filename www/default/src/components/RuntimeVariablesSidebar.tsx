import React, { useEffect, useState } from 'react';
import { getRuntimeVariablesForCategories, RuntimeVariable } from '../utils/runtimeVariables';
import {
  extractAllTemplateVariablesWithLabelsFromObject,
  TemplateVariable,
} from '../utils/templateVariables';

interface RuntimeVariablesSidebarProps {
  category?: string;
  configuration?: any;
  content?: any;
  onMissingVariablesChange?: (count: number) => void;
}

/**
 * Sidebar component that displays all available runtime variables for a given integration category.
 * Shows general variables (available to all) plus category-specific variables in collapsible sections.
 */
const RuntimeVariablesSidebar: React.FC<RuntimeVariablesSidebarProps> = ({
  category,
  configuration,
  content,
  onMissingVariablesChange,
}) => {
  const [generalVariables, setGeneralVariables] = useState<
    Record<string, { label: string; example: string; description?: string }>
  >({});
  const [categoryVariables, setCategoryVariables] = useState<
    Record<string, { label: string; example: string; description?: string }>
  >({});
  const [customVariables, setCustomVariables] = useState<TemplateVariable[]>([]);
  const [missingVariables, setMissingVariables] = useState<TemplateVariable[]>([]);
  const [variablesInUse, setVariablesInUse] = useState<TemplateVariable[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Collapsible section states (all initially collapsed)
  const [generalExpanded, setGeneralExpanded] = useState(false);
  const [categoryExpanded, setCategoryExpanded] = useState(false);
  const [customExpanded, setCustomExpanded] = useState(false);
  const [inUseExpanded, setInUseExpanded] = useState(false);
  const [missingExpanded, setMissingExpanded] = useState(false);

  useEffect(() => {
    const fetchVariables = async () => {
      try {
        setLoading(true);
        setError(null);

        // Fetch general variables
        const general = await getRuntimeVariablesForCategories(['general']);
        setGeneralVariables(general);

        // Fetch category-specific variables if not 'general'
        if (category && category !== 'general') {
          const categoryVars = await getRuntimeVariablesForCategories([category]);
          // Remove general variables from category variables to avoid duplication
          const categorySpecific = Object.fromEntries(
            Object.entries(categoryVars).filter(([key]) => !general[key])
          );
          setCategoryVariables(categorySpecific);
        } else {
          setCategoryVariables({});
        }
      } catch (err: any) {
        console.error('Failed to fetch runtime variables:', err);
        setError('Failed to load runtime variables');
      } finally {
        setLoading(false);
      }
    };

    fetchVariables();
  }, [category]);

  // Extract custom variables from configuration and content
  useEffect(() => {
    // console.log('[RuntimeVariablesSidebar] extractCustomVars useEffect running');
    const extractCustomVars = () => {
      const allVars: TemplateVariable[] = [];

      // Extract from configuration
      if (configuration) {
        const configVars = extractAllTemplateVariablesWithLabelsFromObject(configuration);
        allVars.push(...configVars);
      }

      // Extract from content
      if (content) {
        const contentVars = extractAllTemplateVariablesWithLabelsFromObject(content);
        allVars.push(...contentVars);
      }

      // Deduplicate by name, preferring entries with labels
      const varsMap = new Map<string, TemplateVariable>();
      allVars.forEach(v => {
        const existing = varsMap.get(v.name);
        if (!existing || (!existing.label && v.label)) {
          varsMap.set(v.name, v);
        }
      });

      // Get all valid runtime variable names (general + category-specific)
      const validRuntimeVars = new Set<string>([
        ...Object.keys(generalVariables),
        ...Object.keys(categoryVariables),
      ]);

      // Separate into custom (starting with _) and missing (not valid runtime vars, not starting with _)
      const custom: TemplateVariable[] = [];
      const missing: TemplateVariable[] = [];
      const inUse: TemplateVariable[] = [];

      Array.from(varsMap.values()).forEach(v => {
        if (v.name.startsWith('_')) {
          custom.push(v);
          // Also add to inUse since custom variables are being used
          inUse.push(v);
        } else if (!validRuntimeVars.has(v.name)) {
          missing.push(v);
        } else {
          // Valid runtime variable that is being used
          inUse.push(v);
        }
      });

      setCustomVariables(custom.sort((a, b) => a.name.localeCompare(b.name)));
      const sortedMissing = missing.sort((a, b) => a.name.localeCompare(b.name));
      setMissingVariables(sortedMissing);
      setVariablesInUse(inUse.sort((a, b) => a.name.localeCompare(b.name)));

      // Notify parent component of missing variables count
      if (onMissingVariablesChange) {
        onMissingVariablesChange(sortedMissing.length);
      }
    };

    extractCustomVars();
  }, [configuration, content, generalVariables, categoryVariables, onMissingVariablesChange]);

  const copyToClipboard = (varName: string) => {
    const textToCopy = `\${${varName}}`;
    navigator.clipboard.writeText(textToCopy);
  };

  const renderVariableList = (
    vars: Record<string, { label: string; example: string; description?: string }>
  ) => {
    const entries = Object.entries(vars);
    if (entries.length === 0) {
      return <p className="text-muted small mb-0 ms-3">None available</p>;
    }

    return (
      <div className="ms-3">
        {entries.map(([varName, varInfo]) => (
          <div
            key={varName}
            className="mb-2 p-2 bg-light border rounded cursor-pointer"
            onClick={() => copyToClipboard(varName)}
            style={{ cursor: 'pointer' }}
            title="Click to copy"
          >
            <div className="d-flex justify-content-between align-items-start">
              <div className="flex-grow-1">
                <div className="font-weight-bold small text-primary">{varInfo.label}</div>
                <code className="d-block small text-muted mb-1">${'{' + varName + '}'}</code>
                {varInfo.description && (
                  <p className="mb-1 small text-muted" style={{ fontSize: '0.8em' }}>
                    {varInfo.description}
                  </p>
                )}
                {varInfo.example && (
                  <div className="small text-muted" style={{ fontSize: '0.75em' }}>
                    <em>Example: {varInfo.example}</em>
                  </div>
                )}
              </div>
              <i className="fas fa-copy text-muted ms-2" style={{ fontSize: '0.85em' }}></i>
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderCustomVariableList = (vars: TemplateVariable[]) => {
    if (vars.length === 0) {
      return (
        <p className="text-muted small mb-0 ms-3">
          No custom variables detected. Custom variables must start with underscore (e.g.,{' '}
          <code>${'{_MY_VAR}'}</code>)
        </p>
      );
    }

    return (
      <div className="ms-3">
        {vars.map(variable => (
          <div
            key={variable.name}
            className="mb-2 p-2 bg-light border rounded cursor-pointer"
            onClick={() => copyToClipboard(variable.name)}
            style={{ cursor: 'pointer' }}
            title="Click to copy"
          >
            <div className="d-flex justify-content-between align-items-start">
              <div className="flex-grow-1">
                <div className="font-weight-bold small text-success">
                  {variable.label || variable.name}
                </div>
                <code className="d-block small text-muted mb-1">${'{' + variable.name + '}'}</code>
                <p className="mb-0 small text-muted" style={{ fontSize: '0.8em' }}>
                  User-defined custom variable
                </p>
              </div>
              <i className="fas fa-copy text-muted ms-2" style={{ fontSize: '0.85em' }}></i>
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderInUseVariableList = (vars: TemplateVariable[]) => {
    if (vars.length === 0) {
      return <p className="text-muted small mb-0 ms-3">No runtime variables currently in use</p>;
    }

    return (
      <div className="ms-3">
        {vars.map(variable => (
          <div
            key={variable.name}
            className="mb-2 p-2 bg-light border rounded cursor-pointer"
            onClick={() => copyToClipboard(variable.name)}
            style={{ cursor: 'pointer' }}
            title="Click to copy"
          >
            <div className="d-flex justify-content-between align-items-start">
              <div className="flex-grow-1">
                <div className="font-weight-bold small text-primary">
                  {variable.label || variable.name}
                </div>
                <code className="d-block small text-muted mb-1">${'{' + variable.name + '}'}</code>
              </div>
              <i className="fas fa-copy text-muted ms-2" style={{ fontSize: '0.85em' }}></i>
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderMissingVariableList = (vars: TemplateVariable[]) => {
    if (vars.length === 0) {
      return null;
    }

    return (
      <div className="ms-3">
        {vars.map(variable => (
          <div
            key={variable.name}
            className="mb-2 p-2 bg-light border rounded cursor-pointer"
            onClick={() => copyToClipboard(variable.name)}
            style={{ cursor: 'pointer' }}
            title="Click to copy"
          >
            <div className="d-flex justify-content-between align-items-start">
              <div className="flex-grow-1">
                <div className="font-weight-bold small text-danger">
                  {variable.label || variable.name}
                </div>
                <code className="d-block small text-muted mb-1">${'{' + variable.name + '}'}</code>
                <p className="mb-0 small text-muted" style={{ fontSize: '0.8em' }}>
                  Not a valid runtime variable for this category. Prefix with underscore to use as
                  custom variable.
                </p>
              </div>
              <i className="fas fa-copy text-muted ms-2" style={{ fontSize: '0.85em' }}></i>
            </div>
          </div>
        ))}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-code me-2"></i>
            Integration Variables
          </h6>
        </div>
        <div className="card-body text-center">
          <div className="spinner-border spinner-border-sm text-primary" role="status">
            <span className="visually-hidden"></span>
          </div>
          <p className="mt-2 mb-0 small text-muted">Loading variables...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-code me-2"></i>
            Integration Variables
          </h6>
        </div>
        <div className="card-body">
          <div className="alert alert-warning mb-0">
            <i className="fas fa-exclamation-triangle me-2"></i>
            {error}
          </div>
        </div>
      </div>
    );
  }

  const generalCount = Object.keys(generalVariables).length;
  const categoryCount = Object.keys(categoryVariables).length;
  const customCount = customVariables.length;
  const inUseCount = variablesInUse.length;
  const missingCount = missingVariables.length;

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-code me-2"></i>
          Integration Variables
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted small mb-3">
          Click any variable to copy. Expand sections to see details.
        </p>

        <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
          {/* General Variables Section */}
          <div className="mb-3">
            <div
              className="d-flex justify-content-between align-items-center p-2 bg-light border rounded cursor-pointer"
              onClick={() => setGeneralExpanded(!generalExpanded)}
              style={{ cursor: 'pointer' }}
            >
              <div className="d-flex align-items-center">
                <i
                  className={`fas fa-chevron-${generalExpanded ? 'down' : 'right'} me-2 text-muted`}
                  style={{ fontSize: '0.8em' }}
                ></i>
                <strong className="small">General Variables</strong>
                <span className="badge text-bg-secondary ms-2">{generalCount}</span>
              </div>
            </div>
            {generalExpanded && (
              <div className="mt-2">
                <p className="text-muted small ms-3 mb-2">
                  Available to all integration categories
                </p>
                {renderVariableList(generalVariables)}
              </div>
            )}
          </div>

          {/* Category-Specific Variables Section */}
          {category && category !== 'general' && (
            <div className="mb-3">
              <div
                className="d-flex justify-content-between align-items-center p-2 bg-light border rounded cursor-pointer"
                onClick={() => setCategoryExpanded(!categoryExpanded)}
                style={{ cursor: 'pointer' }}
              >
                <div className="d-flex align-items-center">
                  <i
                    className={`fas fa-chevron-${categoryExpanded ? 'down' : 'right'} me-2 text-muted`}
                    style={{ fontSize: '0.8em' }}
                  ></i>
                  <strong className="small text-capitalize">{category} Variables</strong>
                  <span className="badge text-bg-secondary ms-2">{categoryCount}</span>
                </div>
              </div>
              {categoryExpanded && (
                <div className="mt-2">
                  <p className="text-muted small ms-3 mb-2">
                    Specific to <strong>{category}</strong> category integrations
                  </p>
                  {renderVariableList(categoryVariables)}
                </div>
              )}
            </div>
          )}

          {/* Custom Variables Section */}
          <div className="mb-3">
            <div
              className="d-flex justify-content-between align-items-center p-2 bg-light border rounded cursor-pointer"
              onClick={() => setCustomExpanded(!customExpanded)}
              style={{ cursor: 'pointer' }}
            >
              <div className="d-flex align-items-center">
                <i
                  className={`fas fa-chevron-${customExpanded ? 'down' : 'right'} me-2 text-muted`}
                  style={{ fontSize: '0.8em' }}
                ></i>
                <strong className="small">Custom Variables</strong>
                <span className="badge text-bg-success ms-2">{customCount}</span>
              </div>
            </div>
            {customExpanded && (
              <div className="mt-2">
                <p className="text-muted small ms-3 mb-2">
                  Detected from your templates (must start with underscore)
                </p>
                {renderCustomVariableList(customVariables)}
              </div>
            )}
          </div>

          {/* Variables In Use Section */}
          <div className="mb-3">
            <div
              className="d-flex justify-content-between align-items-center p-2 bg-light border rounded cursor-pointer"
              onClick={() => setInUseExpanded(!inUseExpanded)}
              style={{ cursor: 'pointer' }}
            >
              <div className="d-flex align-items-center">
                <i
                  className={`fas fa-chevron-${inUseExpanded ? 'down' : 'right'} me-2 text-muted`}
                  style={{ fontSize: '0.8em' }}
                ></i>
                <strong className="small">Variables In Use</strong>
                <span className="badge text-bg-secondary ms-2">{inUseCount}</span>
              </div>
            </div>
            {inUseExpanded && (
              <div className="mt-2">
                <p className="text-muted small ms-3 mb-2">
                  Runtime variables currently used in your template
                </p>
                {renderInUseVariableList(variablesInUse)}
              </div>
            )}
          </div>

          {/* Missing Variables Section */}
          {missingCount > 0 && (
            <div className="mb-3">
              <div
                className="d-flex justify-content-between align-items-center p-2 bg-light border rounded cursor-pointer"
                onClick={() => setMissingExpanded(!missingExpanded)}
                style={{ cursor: 'pointer' }}
              >
                <div className="d-flex align-items-center">
                  <i
                    className={`fas fa-chevron-${missingExpanded ? 'down' : 'right'} me-2 text-muted`}
                    style={{ fontSize: '0.8em' }}
                  ></i>
                  <strong className="small">Missing Variables</strong>
                  <span className="badge text-bg-danger ms-2">{missingCount}</span>
                </div>
              </div>
              {missingExpanded && (
                <div className="mt-2">
                  <p className="text-muted small ms-3 mb-2">
                    These variables are not valid for the <strong>{category || 'general'}</strong>{' '}
                    category. Either rename them to start with underscore or use valid runtime
                    variables.
                  </p>
                  {renderMissingVariableList(missingVariables)}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RuntimeVariablesSidebar;
