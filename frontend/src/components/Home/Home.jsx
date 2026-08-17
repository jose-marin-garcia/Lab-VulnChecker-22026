import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Table,
    History,
    ShieldAlert,
    ClipboardList,
    Settings as SettingsIcon,
    Download,
    RefreshCcw,
    AlertCircle,
    ChevronLeft,
    ChevronRight,
} from 'lucide-react';
import { apiClient } from '../../config/auth';
import { EMPTY_STATS, sanitizeStatsPayload } from '../Charts/pieChart';
import { PieCard } from '../Charts/pieChart.jsx';
import './Home.css';
import '../Charts/pieChart.css';

const API_BASE_URL = import.meta.env.VITE_API_URL;
const AGENTS_PAGE_SIZE = 8;

const metricFromSeverity = (severityData, label) => {
    const entry = severityData.find((item) => item.name === label);
    return entry ? entry.value : 0;
};

const Home = () => {
    const [userName] = useState(() => localStorage.getItem('user_name') || 'Usuario');
    const userRole = localStorage.getItem('user_role');
    const navigate = useNavigate();

    const [stats, setStats] = useState(EMPTY_STATS);
    const [loadingCharts, setLoadingCharts] = useState(true);
    const [errorCharts, setErrorCharts] = useState('');

    const [agentRows, setAgentRows] = useState([]);
    const [agentPage, setAgentPage] = useState(0);
    const [agentTotalElements, setAgentTotalElements] = useState(0);
    const [agentTotalPages, setAgentTotalPages] = useState(0);
    const [loadingAgents, setLoadingAgents] = useState(true);
    const [errorAgents, setErrorAgents] = useState('');

    const [agentCveRows, setAgentCveRows] = useState([]);
    const [agentCvePage, setAgentCvePage] = useState(0);
    const [agentCveTotalElements, setAgentCveTotalElements] = useState(0);
    const [agentCveTotalPages, setAgentCveTotalPages] = useState(0);
    const [loadingAgentCves, setLoadingAgentCves] = useState(true);
    const [errorAgentCves, setErrorAgentCves] = useState('');

    const fetchChartStatistics = useCallback(async () => {
        setLoadingCharts(true);
        setErrorCharts('');

        try {
            const response = await apiClient.get(`${API_BASE_URL}/api/vulnerabilities/charts`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const payload = await response.json();
            setStats(sanitizeStatsPayload(payload));
        } catch (fetchError) {
            console.error('Error al obtener estadisticas para graficos:', fetchError);
            setErrorCharts('No se pudo cargar la informacion para los graficos.');
            setStats(EMPTY_STATS);
        } finally {
            setLoadingCharts(false);
        }
    }, []);

    const fetchAgentCounts = useCallback(async (page) => {
        setLoadingAgents(true);
        setErrorAgents('');

        try {
            const params = new URLSearchParams({ page: String(page), size: String(AGENTS_PAGE_SIZE) });
            const response = await apiClient.get(`${API_BASE_URL}/api/vulnerabilities/agent-counts?${params.toString()}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const payload = await response.json();
            const rows = Array.isArray(payload?.content)
                ? payload.content
                    .map((item) => ({
                        name: item?.name ?? 'Sin dato',
                        value: Number(item?.value) || 0,
                    }))
                    .filter((item) => item.value > 0)
                : [];
            setAgentRows(rows);
            setAgentTotalElements(Number(payload?.totalElements) || 0);
            setAgentTotalPages(Number(payload?.totalPages) || 0);
            setAgentPage(page);
        } catch (fetchError) {
            console.error('Error al obtener conteo por agente:', fetchError);
            setErrorAgents('No se pudo cargar el conteo de vulnerabilidades por agente.');
            setAgentRows([]);
        } finally {
            setLoadingAgents(false);
        }
    }, []);

    const fetchAgentCveCounts = useCallback(async (page) => {
        setLoadingAgentCves(true);
        setErrorAgentCves('');

        try {
            const params = new URLSearchParams({ page: String(page), size: String(AGENTS_PAGE_SIZE) });
            const response = await apiClient.get(`${API_BASE_URL}/api/vulnerabilities/agent-cve-counts?${params.toString()}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const payload = await response.json();
            const rows = Array.isArray(payload?.content)
                ? payload.content
                    .map((item) => ({
                        agentName: item?.agentName ?? 'Sin dato',
                        cve: item?.cve ?? 'Sin dato',
                        count: Number(item?.count) || 0,
                    }))
                    .filter((item) => item.count > 0)
                : [];
            setAgentCveRows(rows);
            setAgentCveTotalElements(Number(payload?.totalElements) || 0);
            setAgentCveTotalPages(Number(payload?.totalPages) || 0);
            setAgentCvePage(page);
        } catch (fetchError) {
            console.error('Error al obtener CVEs por agente:', fetchError);
            setErrorAgentCves('No se pudo cargar los CVEs por agente.');
            setAgentCveRows([]);
        } finally {
            setLoadingAgentCves(false);
        }
    }, []);

    useEffect(() => {
        fetchChartStatistics();
        fetchAgentCounts(0);
        fetchAgentCveCounts(0);
    }, [fetchChartStatistics, fetchAgentCounts, fetchAgentCveCounts]);

    const menuItems = [
        { id: 1, title: 'Tablas', icon: <Table size={40} />, desc: 'Visualiza datos crudos de activos.', path: '/filters?view=tables' },
        { id: 2, title: 'Evolución', icon: <History size={40} />, desc: 'Histórico de seguridad en el tiempo.', path: '/evolution' },
        { id: 3, title: 'Críticas', icon: <ShieldAlert size={40} />, desc: 'Vulnerabilidades de severidad crítica.', path: '/filters?view=critical' },
        { id: 4, title: 'Resumen', icon: <ClipboardList size={40} />, desc: 'Visualizar y descargas vulnerabilidades.', path: '/filters?view=summary' },
        ...(userRole === 'ADMIN' ? [
            { id: 5, title: 'Ajustes', icon: <SettingsIcon size={40} />, desc: 'Configuración del sistema y perfil.', path: '/settings' }
        ] : []),
    ];

    const severityData = Array.isArray(stats.severity) ? stats.severity : [];
    const metrics = [
        { label: 'Total', value: stats.total, color: '#5B8CFF' },
        { label: 'Críticas', value: metricFromSeverity(severityData, 'Critical'), color: '#FB7185' },
        { label: 'Altas', value: metricFromSeverity(severityData, 'High'), color: '#F97316' },
        { label: 'Medias', value: metricFromSeverity(severityData, 'Medium'), color: '#F59E0B' },
        { label: 'Bajas', value: metricFromSeverity(severityData, 'Low'), color: '#34D399' },
    ];

    const goToPage = (page) => {
        if (page < 0 || page >= agentTotalPages) return;
        fetchAgentCounts(page);
    };

    const goToPageAgentCve = (page) => {
        if (page < 0 || page >= agentCveTotalPages) return;
        fetchAgentCveCounts(page);
    };

    return (
        <div className="home-container">
            <main className="home-content">
                <header className="welcome-header">
                    <h1 className="welcome-text">¡Bienvenido, {userName}!</h1>
                    <p className="main-subtitle">Panel de Gestión de Vulnerabilidades Institucional USACH</p>
                </header>

                {errorCharts && (
                    <div className="charts-error">
                        <AlertCircle size={18} />
                        <span>{errorCharts}</span>
                    </div>
                )}

                <section className="metrics-grid">
                    {metrics.map((metric) => (
                        <div key={metric.label} className="metric-card">
                            <span className="metric-dot" style={{ backgroundColor: metric.color }} />
                            <div className="metric-info">
                                <strong className="metric-value">{metric.value}</strong>
                                <span className="metric-label">{metric.label}</span>
                            </div>
                        </div>
                    ))}
                </section>

                <section className="dashboard-charts">
                    <div className="dashboard-section-header">
                        <h2>Análisis de Gráficos</h2>
                        <button
                            className="charts-refresh-button"
                            onClick={fetchChartStatistics}
                            disabled={loadingCharts}
                        >
                            <RefreshCcw size={16} className={loadingCharts ? 'spin' : ''} />
                            {loadingCharts ? 'Actualizando...' : 'Actualizar'}
                        </button>
                    </div>

                    {loadingCharts ? (
                        <section className="charts-state">Cargando graficos...</section>
                    ) : stats.total === 0 ? (
                        <section className="charts-state">No hay datos para construir graficos.</section>
                    ) : (
                        <section className="charts-grid">
                            <PieCard title="Por categoria (prioridad)" data={stats.category} />
                            <PieCard title="Por severidad" data={stats.severity} />
                            <PieCard title="Por codigo CVE" data={stats.cve} />
                            <PieCard title="Por paquete" data={stats.package} />
                            <PieCard title="Por agente" data={stats.agent} wide />
                        </section>
                    )}
                </section>

                <section className="agents-table-section">
                    <div className="dashboard-section-header">
                        <h2>Vulnerabilidades por Agente</h2>
                        {loadingAgents && <span className="agents-loading">Cargando...</span>}
                    </div>

                    {errorAgents && (
                        <div className="charts-error">
                            <AlertCircle size={18} />
                            <span>{errorAgents}</span>
                        </div>
                    )}

                    <div className="agents-table-card">
                        <table className="agents-table">
                            <thead>
                                <tr>
                                    <th>Agente</th>
                                    <th>Cantidad de vulnerabilidades</th>
                                </tr>
                            </thead>
                            <tbody>
                                {!loadingAgents && agentRows.length > 0 ? (
                                    agentRows.map((row) => (
                                        <tr key={row.name}>
                                            <td>{row.name}</td>
                                            <td>{row.value}</td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan="2" className="agents-empty">
                                            {loadingAgents ? 'Cargando agentes...' : 'No hay datos de agentes.'}
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>

                        {agentTotalPages > 1 && (
                            <div className="agents-pagination">
                                <button
                                    className="agents-page-button"
                                    onClick={() => goToPage(agentPage - 1)}
                                    disabled={agentPage <= 0 || loadingAgents}
                                >
                                    <ChevronLeft size={16} />
                                </button>
                                <span className="agents-page-info">
                                    Página {agentPage + 1} de {agentTotalPages}
                                </span>
                                <button
                                    className="agents-page-button"
                                    onClick={() => goToPage(agentPage + 1)}
                                    disabled={agentPage >= agentTotalPages - 1 || loadingAgents}
                                >
                                    <ChevronRight size={16} />
                                </button>
                            </div>
                        )}
                        {agentTotalElements > 0 && (
                            <div className="agents-total">Total de agentes: {agentTotalElements}</div>
                        )}
                    </div>
                </section>

                <section className="agents-table-section">
                    <div className="dashboard-section-header">
                        <h2>Top CVEs por Agente</h2>
                        {loadingAgentCves && <span className="agents-loading">Cargando...</span>}
                    </div>

                    {errorAgentCves && (
                        <div className="charts-error">
                            <AlertCircle size={18} />
                            <span>{errorAgentCves}</span>
                        </div>
                    )}

                    <div className="agents-table-card">
                        <table className="agents-table">
                            <thead>
                                <tr>
                                    <th>Agente</th>
                                    <th>CVE</th>
                                    <th>Cantidad</th>
                                </tr>
                            </thead>
                            <tbody>
                                {!loadingAgentCves && agentCveRows.length > 0 ? (
                                    agentCveRows.map((row) => (
                                        <tr key={`${row.agentName}-${row.cve}`}>
                                            <td>{row.agentName}</td>
                                            <td>{row.cve}</td>
                                            <td>{row.count}</td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan="3" className="agents-empty">
                                            {loadingAgentCves ? 'Cargando datos...' : 'No hay datos de CVEs por agente.'}
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>

                        {agentCveTotalPages > 1 && (
                            <div className="agents-pagination">
                                <button
                                    className="agents-page-button"
                                    onClick={() => goToPageAgentCve(agentCvePage - 1)}
                                    disabled={agentCvePage <= 0 || loadingAgentCves}
                                >
                                    <ChevronLeft size={16} />
                                </button>
                                <span className="agents-page-info">
                                    Página {agentCvePage + 1} de {agentCveTotalPages}
                                </span>
                                <button
                                    className="agents-page-button"
                                    onClick={() => goToPageAgentCve(agentCvePage + 1)}
                                    disabled={agentCvePage >= agentCveTotalPages - 1 || loadingAgentCves}
                                >
                                    <ChevronRight size={16} />
                                </button>
                            </div>
                        )}
                        {agentCveTotalElements > 0 && (
                            <div className="agents-total">Total de combinaciones: {agentCveTotalElements}</div>
                        )}
                    </div>
                </section>

                <div className="menu-grid">
                    {menuItems.map((item) => (
                        <button
                            key={item.id}
                            className="menu-card"
                            onClick={() => navigate(item.path)}
                        >
                            <div className="icon-wrapper">{item.icon}</div>
                            <div className="card-info">
                                <h3>{item.title}</h3>
                                <p>{item.desc}</p>
                            </div>
                        </button>
                    ))}

                    <button
                        className="menu-card wazuh-button"
                        onClick={() => navigate('/consumer')}
                        style={{ gridColumn: '1 / -1' }}
                    >
                        <div className="icon-wrapper">
                            <Download size={40} />
                        </div>
                        <div className="card-info">
                            <h3>Obtener datos desde Wazuh</h3>
                            <p>Consume la API de uno o más Wazuh</p>
                        </div>
                    </button>
                </div>
            </main>
        </div>
    );
};

export default Home;
