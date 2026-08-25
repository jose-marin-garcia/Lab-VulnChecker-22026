import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    ShieldCheck, Lock, User, Server, Database, Edit2, X,
    Users, Check, Trash2, UserCheck, List as ListIcon
} from 'lucide-react';
import { apiClient } from '../../config/auth';
import './Settings.css';

const API_BASE_URL = import.meta.env.VITE_API_URL;

const Settings = () => {
    const navigate = useNavigate();

    // Estados Infraestructura
    const [infraName, setInfraName] = useState('');
    const [wazuhIp, setWazuhIp] = useState('');
    const [wazuhUser, setWazuhUser] = useState('');
    const [wazuhPass, setWazuhPass] = useState('');
    const [infraCredentials, setInfraCredentials] = useState([]);

    // Estados Admin (Gestión de Usuarios)
    const [pendingUsers, setPendingUsers] = useState([]);
    const [agentsList, setAgentsList] = useState([]);
    const [selectedAgents, setSelectedAgents] = useState({}); // { userId: { agentId, agentName } }
    const userRole = localStorage.getItem('user_role'); // USER o ADMIN

    // Estados de Control
    const [loading, setLoading] = useState(false);
    const [editingId, setEditingId] = useState(null);
    const [showVerifyModal, setShowVerifyModal] = useState(false);
    const [userPasswordVerify, setUserPasswordVerify] = useState('');
    const userId = localStorage.getItem('user_id');

    const fetchData = useCallback(async () => {
        if (!userId) return;

        try {
            const resInfra = await apiClient.get(`${API_BASE_URL}/api/infra-credentials/user/${userId}`);
            if (resInfra.ok) setInfraCredentials(await resInfra.json());

            if (userRole === 'ADMIN') {
                const resUsers = await apiClient.get(`${API_BASE_URL}/api/users/pending`);
                if (resUsers.ok) setPendingUsers(await resUsers.json());

                // Cargar lista de agentes
                const resAgents = await apiClient.get(`${API_BASE_URL}/api/users/agents`);
                if (resAgents.ok) setAgentsList(await resAgents.json());
            }
        } catch (error) {
            console.error('Error al cargar datos:', error);
        }
    }, [userId, userRole]);

    useEffect(() => { fetchData(); }, [fetchData]);

    // --- LÓGICA DE ADMINISTRACIÓN ---
    const handleAgentSelect = (userId, value) => {
        if (!value) {
            setSelectedAgents(prev => {
                const copy = { ...prev };
                delete copy[userId];
                return copy;
            });
            return;
        }
        const agent = agentsList.find(a => a.agentId === value);
        if (agent) {
            setSelectedAgents(prev => ({
                ...prev,
                [userId]: { agentId: agent.agentId, agentName: agent.agentName }
            }));
        }
    };

    const handleActivateUser = async (id) => {
        const selected = selectedAgents[id];
        if (!selected) {
            alert("Debes seleccionar un agente antes de activar al usuario.");
            return;
        }
        if (!window.confirm(`¿Confirmas la activación de este usuario con el agente "${selected.agentName}"?`)) return;
        try {
            const res = await apiClient.patch(`${API_BASE_URL}/api/users/${id}/activate`, {
                agentId: selected.agentId,
                agentName: selected.agentName
            });
            if (res.ok) fetchData();
        } catch (error) { console.error('Error:', error); }
    };

    const handleDeleteUser = async (id) => {
        if (!window.confirm("¿Estás seguro de rechazar/eliminar esta solicitud?")) return;
        try {
            const res = await apiClient.delete(`${API_BASE_URL}/api/users/${id}`);
            if (res.ok) fetchData();
        } catch (error) { console.error('Error:', error); }
    };

    // --- LÓGICA DE INFRAESTRUCTURA ---
    const startEdit = (cred) => {
        setEditingId(cred.id);
        setInfraName(cred.name);
        setWazuhIp(cred.wazuhIp);
        setWazuhUser(cred.wazuhUser);
        setWazuhPass('');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    const cancelEdit = () => {
        setEditingId(null);
        setInfraName(''); setWazuhIp(''); setWazuhUser(''); setWazuhPass('');
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        setShowVerifyModal(true);
    };

    const handleVerifyAndSave = async () => {
        setLoading(true);
        // Aquí iría tu fetch real de validación de password contra el backend
        const isPasswordCorrect = true;

        if (!isPasswordCorrect) {
            alert("Contraseña incorrecta");
            setLoading(false);
            return;
        }

        const payload = {
            userId,
            name: infraName,
            wazuhIp,
            wazuhUser,
            wazuhPassword: wazuhPass
        };

        try {
            const url = editingId
                ? `${API_BASE_URL}/api/infra-credentials/${editingId}`
                : `${API_BASE_URL}/api/infra-credentials`;
            const response = editingId
                ? await apiClient.put(url, payload)
                : await apiClient.post(url, payload);

            if (response.ok) {
                cancelEdit();
                fetchData();
                setShowVerifyModal(false);
                setUserPasswordVerify('');
                window.dispatchEvent(new CustomEvent('reloadCredentials')); // Actualiza lista en layout
            }
        } catch (error) { console.error(error); }
        finally { setLoading(false); }
    };

    return (
        <div className="settings-container">
            {/* MODAL DE VERIFICACIÓN */}
            {showVerifyModal && (
                <div className="modal-overlay">
                    <form className="modal-content" onSubmit={(e) => { e.preventDefault(); handleVerifyAndSave(); }}>
                        <div className="modal-header">
                            <div className="modal-icon-wrapper"><ShieldCheck size={28} color="#007bff" /></div>
                            <h3>Verificación de Seguridad</h3>
                            <button type="button" className="close-modal-x" onClick={() => setShowVerifyModal(false)}><X size={20} /></button>
                        </div>
                        <p className="modal-description">
                            Ingresa tu contraseña para confirmar los cambios en <strong>{infraName}</strong>.
                        </p>
                        <div className="form-group">
                            <label><Lock size={14} /> Contraseña de acceso</label>
                            <input
                                type="password"
                                value={userPasswordVerify}
                                onChange={(e) => setUserPasswordVerify(e.target.value)}
                                placeholder="Escribe tu contraseña"
                                autoFocus required className="modal-input"
                            />
                        </div>
                        <div className="modal-actions">
                            <button type="button" className="cancel-button" onClick={() => setShowVerifyModal(false)}>Cancelar</button>
                            <button type="submit" className="confirm-button" disabled={loading || !userPasswordVerify}>
                                {loading ? 'Procesando...' : 'Confirmar'}
                            </button>
                        </div>
                    </form>
                </div>
            )}

            <main className="settings-content">

                {/* --- SECCIÓN ADMINISTRADOR: USUARIOS PENDIENTES --- */}
                {userRole === 'ADMIN' && (
                    <section className="settings-section admin-box">
                        <div className="section-header">
                            <Users className="section-icon admin-icon" />
                            <div>
                                <h2>Aprobación de Usuarios</h2>
                                <p>Solicitudes de acceso pendientes de revisión.</p>
                            </div>
                            <button
                                className="view-users-btn"
                                onClick={() => navigate('/users-list')}
                                style={{ marginLeft: 'auto' }}
                            >
                                <ListIcon size={16} /> Ver Lista de Usuarios
                            </button>
                        </div>

                        <div className="pending-list">
                            {pendingUsers.length === 0 ? (
                                <p className="empty-msg">No hay usuarios esperando aprobación.</p>
                            ) : (
                                <table className="creds-table">
                                    <thead>
                                        <tr>
                                            <th>Nombre Completo</th>
                                            <th>Email</th>
                                            <th>Agente<br/><small>nombre - grupo</small></th>
                                            <th>Acciones</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {pendingUsers.map(u => (
                                            <tr key={u.id}>
                                                <td>{`${u.firstName} ${u.paternalLastName} ${u.maternalLastName}`}</td>
                                                <td style={{ color: '#888' }}>{u.email}</td>
                                                <td>
                                                    <select
                                                        className="agent-select"
                                                        value={selectedAgents[u.id]?.agentId || ''}
                                                        onChange={(e) => handleAgentSelect(u.id, e.target.value)}
                                                    >
                                                        <option value="">-- Seleccionar Agente --</option>
                                                        {agentsList.map(agent => (
                                                            <option key={agent.agentId} value={agent.agentId}>
                                                                {agent.agentName} - {agent.agentGroup}
                                                            </option>
                                                        ))}
                                                    </select>
                                                </td>
                                                <td>
                                                    <div className="admin-actions">
                                                        <button
                                                            className="approve-btn"
                                                            onClick={() => handleActivateUser(u.id)}
                                                            title="Activar Usuario"
                                                            disabled={!selectedAgents[u.id]}
                                                        >
                                                            <UserCheck size={16} />
                                                        </button>
                                                        <button
                                                            className="delete-btn"
                                                            onClick={() => handleDeleteUser(u.id)}
                                                            title="Rechazar"
                                                        >
                                                            <Trash2 size={16} />
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    </section>
                )}

                {/* --- SECCIÓN INFRAESTRUCTURA --- */}
                <section className={`settings-section ${editingId ? 'editing-mode' : ''}`}>
                    <div className="section-header">
                        <Server className="section-icon" />
                        <div>
                            <h2 className={editingId ? 'editing-title' : ''}>
                                {editingId ? 'Editando Perfil' : 'Llavero de Credenciales'}
                            </h2>
                            <p>{editingId ? `Modificando: ${infraName}` : 'Configura accesos SSH y Wazuh.'}</p>
                        </div>
                        {editingId && (
                            <button onClick={cancelEdit} className="cancel-edit-btn" style={{ marginLeft: 'auto' }}>
                                <X size={16} /> Cancelar Edición
                            </button>
                        )}
                    </div>

                    <form className="credential-form" onSubmit={handleSubmit}>
                        <div className="form-grid">
                            <div className="form-group">
                                <label><Database size={16} /> Nombre del Perfil</label>
                                <input type="text" value={infraName} onChange={(e) => setInfraName(e.target.value)} required />
                            </div>
                            <div className="form-group">
                                <label><Server size={15} /> Wazuh IP</label>
                                <input type="text" value={wazuhIp} onChange={(e) => setWazuhIp(e.target.value)} required />
                            </div>
                            <div className="form-group">
                                <label><User size={14} /> Usuario Wazuh</label>
                                <input type="text" value={wazuhUser} onChange={(e) => setWazuhUser(e.target.value)} required />
                            </div>
                            <div className="form-group">
                                <label><Lock size={14} /> Pass Wazuh {editingId && '(Nueva)'}</label>
                                <input type="password" value={wazuhPass} onChange={(e) => setWazuhPass(e.target.value)} placeholder="••••" required={!editingId} />
                            </div>
                        </div>
                        <button type="submit" className="save-button infra-btn" disabled={loading}>
                            {editingId ? 'Actualizar Datos del Perfil' : 'Guardar Perfil'}
                        </button>
                    </form>

                    <div className="credentials-list">
                        <h3>Perfiles Registrados</h3>
                        <table className="creds-table">
                            <thead>
                                <tr>
                                    <th>Perfil</th>
                                    <th>SSH / Wazuh</th>
                                    <th>Acciones</th>
                                </tr>
                            </thead>
                            <tbody>
                                {infraCredentials.map((cred) => (
                                    <tr key={cred.id} style={editingId === cred.id ? { backgroundColor: 'rgba(0, 123, 255, 0.05)' } : {}}>
                                        <td style={{ fontWeight: 'bold' }}>{cred.name}</td>
                                        <td>{cred.sshUser} / {cred.wazuhUser}</td>
                                        <td>
                                            <button className="edit-btn" onClick={() => startEdit(cred)}>
                                                <Edit2 size={12} /> Editar
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </section>
            </main>
        </div>
    );
};

export default Settings;