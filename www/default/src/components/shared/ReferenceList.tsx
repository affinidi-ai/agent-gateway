import React from 'react';
import { ReferenceConflict, referenceKindLabel } from '../../utils/referenceConflict';

interface ReferenceListProps {
  conflict: ReferenceConflict;
  testId: string;
}

/** The things that still use an item, by kind and name, and how many more the user cannot view. */
const ReferenceList: React.FC<ReferenceListProps> = ({ conflict, testId }) => (
  <ul className="mb-0" data-testid={testId}>
    {conflict.references.map(reference => (
      <li key={`${reference.kind}:${reference.id}`}>
        {referenceKindLabel(reference.kind)}: <strong>{reference.name}</strong>
      </li>
    ))}
    {conflict.hiddenReferences > 0 && (
      <li data-testid={`${testId}-hidden`}>and {conflict.hiddenReferences} more you cannot view</li>
    )}
  </ul>
);

export default ReferenceList;
