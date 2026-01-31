import { useState, useEffect } from 'preact/hooks';
import './styles.css';

interface Route {
  code: string;
  url: string;
  expires_at: string;
  uses: number;
  last_access: string;
  created_at: string;
}

interface FormData {
  url: string;
  code: string;
  expiry: string;
}

export function AdminApp() {
  const [routes, setRoutes] = useState<Route[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingCode, setEditingCode] = useState<string | null>(null);
  const [formData, setFormData] = useState<FormData>({
    url: '',
    code: '',
    expiry: '1d'
  });

  useEffect(() => {
    loadRoutes();
  }, []);

  const loadRoutes = async () => {
    try {
      const response = await fetch('/api/routes');
      if (!response.ok) {
        if (response.status === 401) {
          window.location.href = '/login';
          return;
        }
        throw new Error('Failed to load routes');
      }
      const data = await response.json();
      setRoutes(data || []);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const createRoute = async (e: Event) => {
    e.preventDefault();
    
    try {
      const response = await fetch('/api/routes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      if (!response.ok) {
        const error = await response.text();
        alert(`Error: ${error}`);
        return;
      }

      setShowForm(false);
      setFormData({ url: '', code: '', expiry: '1d' });
      await loadRoutes();
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const updateRoute = async (code: string) => {
    try {
      const response = await fetch(`/api/routes/${code}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      if (!response.ok) {
        const error = await response.text();
        alert(`Error: ${error}`);
        return;
      }

      setEditingCode(null);
      setFormData({ url: '', code: '', expiry: '1d' });
      await loadRoutes();
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const deleteRoute = async (code: string) => {
    if (!confirm('Are you sure you want to delete this route?')) {
      return;
    }

    try {
      const response = await fetch(`/api/routes/${code}`, {
        method: 'DELETE'
      });

      if (!response.ok) {
        throw new Error('Failed to delete route');
      }

      await loadRoutes();
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const startEdit = (route: Route) => {
    setEditingCode(route.code);
    setFormData({
      url: route.url,
      code: route.code,
      expiry: getExpiryType(route.expires_at)
    });
  };

  const getExpiryType = (expiresAt: string): string => {
    const now = new Date();
    const expires = new Date(expiresAt);
    const days = Math.round((expires.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    
    if (days <= 1) return '1d';
    if (days <= 7) return '7d';
    if (days <= 30) return '30d';
    if (days <= 365) return '365d';
    return 'perma';
  };

  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleString();
  };

  if (loading) {
    return <p aria-busy="true">Loading...</p>;
  }

  return (
    <main className="container">
      <header>
        <h1>Admin Dashboard</h1>
        <nav>
          <ul>
            <li><a href="/" role="button">Home</a></li>
            <li><a href="/auth/logout" role="button" className="secondary">Logout</a></li>
          </ul>
        </nav>
      </header>

      <article>
        <header>
          <h2>Routes</h2>
          <button onClick={() => setShowForm(!showForm)}>
            {showForm ? 'Cancel' : 'Create New'}
          </button>
        </header>

        {showForm && (
          <form onSubmit={createRoute}>
            <label>
              URL
              <input 
                type="url" 
                value={formData.url}
                onInput={(e) => setFormData({ ...formData, url: (e.target as HTMLInputElement).value })}
                required
              />
            </label>
            <label>
              Custom Code (optional)
              <input 
                type="text" 
                value={formData.code}
                onInput={(e) => setFormData({ ...formData, code: (e.target as HTMLInputElement).value })}
              />
            </label>
            <label>
              Expiry
              <select 
                value={formData.expiry}
                onChange={(e) => setFormData({ ...formData, expiry: (e.target as HTMLSelectElement).value })}
              >
                <option value="1d">1 Day</option>
                <option value="7d">7 Days</option>
                <option value="30d">30 Days</option>
                <option value="365d">365 Days</option>
                <option value="perma">Permanent</option>
              </select>
            </label>
            <button type="submit">Create</button>
          </form>
        )}

        <table>
          <thead>
            <tr>
              <th>Code</th>
              <th>URL</th>
              <th>Uses</th>
              <th>Last Access</th>
              <th>Expires</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {routes.map(route => (
              <tr key={route.code}>
                <td>
                  <a href={`/${route.code}`} target="_blank" rel="noopener noreferrer">
                    /{route.code}
                  </a>
                </td>
                <td>
                  {editingCode === route.code ? (
                    <input 
                      type="url" 
                      value={formData.url}
                      onInput={(e) => setFormData({ ...formData, url: (e.target as HTMLInputElement).value })}
                      aria-label={`Edit URL for route ${route.code}`}
                    />
                  ) : (
                    <small>{route.url}</small>
                  )}
                </td>
                <td>{route.uses || 0}</td>
                <td>
                  <small>
                    {route.last_access ? formatDate(route.last_access) : 'Never'}
                  </small>
                </td>
                <td>
                  {editingCode === route.code ? (
                    <select 
                      value={formData.expiry}
                      onChange={(e) => setFormData({ ...formData, expiry: (e.target as HTMLSelectElement).value })}
                      aria-label={`Edit expiry for route ${route.code}`}
                    >
                      <option value="1d">1 Day</option>
                      <option value="7d">7 Days</option>
                      <option value="30d">30 Days</option>
                      <option value="365d">365 Days</option>
                      <option value="perma">Permanent</option>
                    </select>
                  ) : (
                    <small>{formatDate(route.expires_at)}</small>
                  )}
                </td>
                <td>
                  {editingCode === route.code ? (
                    <>
                      <button 
                        className="secondary"
                        onClick={() => updateRoute(route.code)}
                      >
                        Save
                      </button>
                      {' '}
                      <button 
                        className="secondary"
                        onClick={() => {
                          setEditingCode(null);
                          setFormData({ url: '', code: '', expiry: '1d' });
                        }}
                      >
                        Cancel
                      </button>
                    </>
                  ) : (
                    <>
                      <button 
                        className="secondary"
                        onClick={() => startEdit(route)}
                        aria-label={`Edit route ${route.code}`}
                      >
                        Edit
                      </button>
                      {' '}
                      <button 
                        className="contrast"
                        onClick={() => deleteRoute(route.code)}
                        aria-label={`Delete route ${route.code}`}
                      >
                        Delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </article>
    </main>
  );
}
