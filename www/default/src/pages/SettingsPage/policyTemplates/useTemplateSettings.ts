import { useState } from 'react';
import { renderTemplate, sampleParameterValues } from './regoTemplate';
import {
  initialFieldText,
  missingSettings,
  renderPreview,
  renderWithText,
} from './templateSettings';
import type { FieldText, PolicyTemplate } from './types';

/**
 * The settings of one template and the Rego they render to, starting from `initialText` or the
 * defaults. Callers key the component that uses it by template id, so choosing another
 * template starts over.
 */
export function useTemplateSettings(template: PolicyTemplate, initialText?: FieldText) {
  const [fieldText, setFieldText] = useState<FieldText>(
    () => initialText ?? initialFieldText(template)
  );
  const rendered = renderWithText(template, fieldText);
  const preview = renderPreview(template, fieldText);
  const missing = missingSettings(template, fieldText);
  // The examples hold for the settings they were written with: the defaults and the samples.
  const usesDefaultSettings =
    rendered.rego === renderTemplate(template, sampleParameterValues(template)).rego;
  const setField = (key: string, value: string) =>
    setFieldText(prev => ({ ...prev, [key]: value }));
  return { fieldText, setField, rendered, preview, missing, usesDefaultSettings };
}

export type TemplateSettings = ReturnType<typeof useTemplateSettings>;
