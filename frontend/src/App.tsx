import { useState } from 'preact/hooks';

interface CreateRouteRequest {
  url: string;
  code?: string;
  expiry?: string;
}

interface RouteResponse {
  code: string;
  url: string;
  expires_at: string;
  uses: number;
  last_access: string;
  created_at: string;
}

export function App() {
  const [url, setUrl] = useState('');
  const [code, setCode] = useState('');
  const [expiry, setExpiry] = useState('1d');
  const [result, setResult] = useState<RouteResponse | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError('');
    setResult(null);
    setLoading(true);

    const data: CreateRouteRequest = {
      url,
      expiry
    };
    
    if (code) {
      data.code = code;
    }

    try {
      const response = await fetch('/api/routes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });

      if (!response.ok) {
        const errorText = await response.text();
        setError(errorText || 'Failed to create short URL');
        return;
      }

      const resultData: RouteResponse = await response.json();
      setResult(resultData);
      setUrl('');
      setCode('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    if (result) {
      const shortUrl = `${window.location.origin}/${result.code}`;
      navigator.clipboard.writeText(shortUrl).then(() => {
        alert('Copied to clipboard!');
      });
    }
  };

  return (
    <main className="container">
      <h1>URL Shortener</h1>
      <article>
        <h2>Create Short Link</h2>
        <form onSubmit={handleSubmit}>
          <label>
            URL
            <input
              type="url"
              value={url}
              onInput={(e) => setUrl((e.target as HTMLInputElement).value)}
              placeholder="https://example.com"
              required
              disabled={loading}
            />
          </label>
          <label>
            Custom Code (optional)
            <input
              type="text"
              value={code}
              onInput={(e) => setCode((e.target as HTMLInputElement).value)}
              placeholder="my-link"
              disabled={loading}
            />
          </label>
          <label>
            Expiry
            <select
              value={expiry}
              onChange={(e) => setExpiry((e.target as HTMLSelectElement).value)}
              disabled={loading}
            >
              <option value="1d">1 Day</option>
              <option value="7d">7 Days</option>
            </select>
          </label>
          <button type="submit" disabled={loading} aria-busy={loading}>
            {loading ? 'Creating...' : 'Shorten'}
          </button>
        </form>
        
        {error && (
          <div style={{ color: 'red', marginTop: '1rem' }} role="alert">
            {error}
          </div>
        )}
        
        {result && (
          <div style={{ marginTop: '1rem' }} role="status">
            <p>
              <strong>Short URL:</strong>{' '}
              <a href={`/${result.code}`} target="_blank" rel="noopener noreferrer">
                {window.location.origin}/{result.code}
              </a>
            </p>
            <button type="button" onClick={copyToClipboard}>
              Copy to Clipboard
            </button>
          </div>
        )}
      </article>
      <footer>
        <p>
          <a href="/admin">Admin Login</a>
        </p>
      </footer>
    </main>
  );
}
