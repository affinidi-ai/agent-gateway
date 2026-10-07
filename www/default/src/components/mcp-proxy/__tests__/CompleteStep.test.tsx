import React from 'react';
import { render, screen } from '@testing-library/react';
import CompleteStep from '../CompleteStep';

const renderStep = (proxy: { name: string; warnings?: string[] }) =>
  render(<CompleteStep proxy={proxy} onFinish={jest.fn()} onViewProxy={jest.fn()} />);

describe('MCP Proxy wizard CompleteStep', () => {
  it('reports a clean create as ready to use', () => {
    renderStep({ name: 'Pets' });
    expect(screen.getByText('MCP Proxy Created Successfully!')).toBeInTheDocument();
    expect(screen.getByText('The MCP Proxy is now running and ready to use')).toBeInTheDocument();
    expect(screen.queryByTestId('mcp-proxy-write-warnings')).not.toBeInTheDocument();
  });

  it('shows every create warning instead of claiming the proxy is ready', () => {
    const warnings = [
      'OpenAPI spec is unavailable to the MCP 2024-11-05 tool catalog, so 2024-11-05 clients cannot use this proxy: bad $ref',
      'second warning',
    ];
    renderStep({ name: 'Schemas', warnings });
    expect(screen.getByText('MCP Proxy Created with Warnings')).toBeInTheDocument();
    const alert = screen.getByTestId('mcp-proxy-write-warnings');
    expect(alert).toHaveAttribute('role', 'alert');
    for (const warning of warnings) {
      expect(screen.getByText(warning)).toBeInTheDocument();
    }
    expect(
      screen.queryByText('The MCP Proxy is now running and ready to use')
    ).not.toBeInTheDocument();
    expect(
      screen.getByText('Resolve the warnings above before relying on this proxy')
    ).toBeInTheDocument();
  });

  it('treats an empty warnings list as a clean create', () => {
    renderStep({ name: 'Pets', warnings: [] });
    expect(screen.getByText('MCP Proxy Created Successfully!')).toBeInTheDocument();
    expect(screen.queryByTestId('mcp-proxy-write-warnings')).not.toBeInTheDocument();
  });
});
