import React, { useState, useEffect, useCallback } from 'react';
import { Send, Loader2 } from 'lucide-react';
import { apiClient } from '../../config/auth';

const API_BASE_URL = import.meta.env.VITE_API_URL;

export default function Consumer() {
    const userId = localStorage.getItem('user_id');

    const [availableCredentials, setAvailableCredentials] = useState([]);
    const [selectedCredential, setSelectedCredential] = useState('');
    const [loading, setLoading] = useState(false);
    const [progressCount, setProgressCount] = useState(0);
    const [totalTarget, setTotalTarget] = useState(0);
    const [error, setError] = useState(null);

    // --- FUNCIÓN EXTRAÍDA PARA PODER REUTILIZARLA ---
    const fetchCredentials = useCallback(async () => {
        if (!userId) return;
        try {
            const response = await apiClient.get(`${API_BASE_URL}/api/infra-credentials/user/${userId}`);
            if (response.ok) {
                const data = await response.json();
                setAvailableCredentials(data);
            }
        } catch (error) {
            console.error('Error cargando credenciales:', error);
        }
    }, [userId]);

    // Polling de progreso
    useEffect(() => {
        let interval;
        if (loading) {
            interval = setInterval(async () => {
                try {
                    const res = await apiClient.get(`${API_BASE_URL}/api/vulns/count-local`);
                    if (res.ok) {
                        const data = await res.json();
                        setProgressCount(data.count);

                        if (data.status === 'ERROR') {
                            setError(data.error || 'Error durante la sincronización en el servidor.');
                            setLoading(false);
                        } else if (data.status === 'COMPLETED') {
                            setLoading(false);
                        } else if (data.count >= totalTarget && totalTarget > 0) {
                            setLoading(false);
                        }
                    }
                } catch (err) {
                    console.error("Error en polling:", err);
                }
            }, 2000);
        }
        return () => clearInterval(interval);
    }, [loading, totalTarget]);

    // Carga inicial al montar el componente o cambiar de usuario
    useEffect(() => {
        fetchCredentials();
    }, [fetchCredentials]);

    // Escuchar el evento de recarga desde otras páginas
    useEffect(() => {
        const handleCustomReload = () => {
            fetchCredentials();
        };

        window.addEventListener('reloadCredentials', handleCustomReload);

        return () => {
            window.removeEventListener('reloadCredentials', handleCustomReload);
        };
    }, [fetchCredentials]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!selectedCredential) return;

        setLoading(true);
        setProgressCount(0);
        setError(null);
        setTotalTarget(0);

        try {
            const countRes = await apiClient.post(`${API_BASE_URL}/api/vulns/remote-count`, {
                infrastructureCredentialId: parseInt(selectedCredential)
            });

            if (!countRes.ok) {
                const errorData = await countRes.json().catch(() => ({}));
                setError(errorData.message || 'Error al conectar.');
                setLoading(false);
                return;
            }

            const data = await countRes.json();
            setTotalTarget(data.total || 0);

            const consumeRes = await apiClient.post(`${API_BASE_URL}/api/vulns/consume`, {
                infrastructureCredentialId: parseInt(selectedCredential)
            });

            if (!consumeRes.ok) {
                const errorData = await consumeRes.json().catch(() => ({}));
                setError(errorData.message || 'Error al iniciar la sincronización.');
                setLoading(false);
                return;
            }
        } catch (err) {
            console.error("Error iniciando consumo:", err);
            setError('Error de conexión.');
            setLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} style={{ display: 'flex', alignItems: 'center', gap: '10px', margin: 0 }}>
            <select
                value={selectedCredential}
                onChange={(e) => setSelectedCredential(e.target.value)}
                disabled={loading}
                required
                style={{
                    padding: '6px 12px',
                    borderRadius: '6px',
                    border: '1px solid #e5e7eb',
                    backgroundColor: '#f9fafb',
                    fontSize: '14px',
                    color: '#111827',
                    minWidth: '180px',
                    outline: 'none',
                    cursor: loading ? 'not-allowed' : 'pointer'
                }}
            >
                <option value="">Seleccionar Credencial</option>
                {availableCredentials.map(c => (
                    <option key={c.id} value={c.id}>{c.name}</option>
                ))}
            </select>

            <button
                type="submit"
                disabled={loading || !selectedCredential}
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '6px 16px',
                    borderRadius: '6px',
                    border: 'none',
                    backgroundColor: loading ? '#9ca3af' : '#2563eb',
                    color: '#fff',
                    cursor: loading || !selectedCredential ? 'not-allowed' : 'pointer',
                    fontSize: '14px',
                    fontWeight: '500',
                    transition: 'background-color 0.2s',
                    whiteSpace: 'nowrap'
                }}
            >
                {loading ? (
                    <>
                        <Loader2 size={16} className="spinner" style={{ animation: 'spin 1s linear infinite' }} />
                        <span>{progressCount} / {totalTarget}</span>
                    </>
                ) : (
                    <>
                        <Send size={16} />
                        <span>Consumir</span>
                    </>
                )}
            </button>
            {error && <span style={{ color: '#ef4444', fontSize: '12px', marginLeft: '10px', whiteSpace: 'nowrap' }}>{error}</span>}
            <style>
                {`
                    @keyframes spin {
                        from { transform: rotate(0deg); }
                        to { transform: rotate(360deg); }
                    }
                `}
            </style>
        </form>
    );
}