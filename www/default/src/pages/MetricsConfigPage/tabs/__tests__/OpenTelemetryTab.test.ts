import { swapDefaultPort } from '../OpenTelemetryTab';

describe('swapDefaultPort', () => {
  it('swaps the gRPC default port to the HTTP default when switching to http', () => {
    expect(swapDefaultPort('http://localhost:4317', 'http')).toBe('http://localhost:4318');
  });

  it('swaps the HTTP default port to the gRPC default when switching to grpc', () => {
    expect(swapDefaultPort('http://localhost:4318', 'grpc')).toBe('http://localhost:4317');
  });

  it('preserves scheme and host when swapping', () => {
    expect(swapDefaultPort('https://collector.example.com:4317', 'http')).toBe(
      'https://collector.example.com:4318'
    );
  });

  it('leaves a custom (non-default) port untouched', () => {
    expect(swapDefaultPort('http://localhost:9999', 'http')).toBe('http://localhost:9999');
  });

  it('does not swap when the port already matches the target protocol default', () => {
    expect(swapDefaultPort('http://localhost:4318', 'http')).toBe('http://localhost:4318');
    expect(swapDefaultPort('http://localhost:4317', 'grpc')).toBe('http://localhost:4317');
  });

  it('leaves an endpoint with no port untouched', () => {
    expect(swapDefaultPort('http://localhost', 'http')).toBe('http://localhost');
  });

  it('preserves a trailing path when swapping the port', () => {
    expect(swapDefaultPort('https://collector.example.com:4317/otlp', 'http')).toBe(
      'https://collector.example.com:4318/otlp'
    );
  });

  it('does not swap a default-looking number that appears in the path only', () => {
    expect(swapDefaultPort('http://localhost/4317', 'http')).toBe('http://localhost/4317');
  });
});
