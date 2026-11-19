import { useState } from 'react';
import { defaultParameterValues, renderTemplate } from './regoTemplate';
import { initialFieldText, renderWithText } from './templateSettings';
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
  const usesDefaultSettings =
    rendered.rego === renderTemplate(template, defaultParameterValues(template)).rego;
  const setField = (key: string, value: string) =>
    setFieldText(prev => ({ ...prev, [key]: value }));
  return { fieldText, setField, rendered, usesDefaultSettings };
}

export type TemplateSettings = ReturnType<typeof useTemplateSettings>;
