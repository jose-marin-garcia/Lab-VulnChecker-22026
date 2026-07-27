import { useCallback, useEffect, useState, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { AlertCircle, RefreshCcw, Filter } from 'lucide-react';
import { apiClient } from '../../config/auth';
import TimelinePanel from '../Timeline/TimelinePanel';
import './Tables.css';

const API_BASE_URL = import.meta.env.VITE_API_URL;
const API_URL = `${API_BASE_URL}/api/vulnerabilities`;
const FILTERS_URL = `${API_BASE_URL}/api/vulnerabilities/filters`;
const PAGE_SIZE = 12;

const formatDate = (dateValue) => {
  if (!dateValue) return "-";
  const parsedDate = new Date(dateValue);
  if (Number.isNaN(parsedDate.getTime())) return dateValue;
  return parsedDate.toLocaleString("es-CL");
};

const truncateText = (value, max = 120) => {
  if (!value) return "-";
  return value.length > max ? `${value.slice(0, max)}...` : value;
};

const Tables = ({
  title = "Explorador de Activos",
  subtitle = "Visualización en crudo de vulnerabilidades y paquetes detectados.",
  defaultHighPriorityOnly = false,
  lockHighPriority = false,
  hideSeverityFilter = false,
}) => {
  const [searchParams] = useSearchParams();
  const defaultFilters = {
    severity: searchParams.get("severity") || "all",
    status: searchParams.get("status") || "all",
    startDate: searchParams.get("startDate") || "",
    endDate: searchParams.get("endDate") || "",
    cvss: { min: Number(searchParams.get("minCvss")) || 0, max: Number(searchParams.get("maxCvss")) || 10 },
    agentName: searchParams.get("agentName") || "",
    agentGroup: searchParams.get("agentGroup") || "",
    cve: searchParams.get("cve") || "",
    package: searchParams.get("packageName") || "",
  };

  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [appliedFilters, setAppliedFilters] = useState(defaultFilters);
  const [localFilters, setLocalFilters] = useState(defaultFilters);

  const [openFilterPopover, setOpenFilterPopover] = useState(null);
  const popoverRef = useRef(null);

  const [highPriorityOnly, setHighPriorityOnly] = useState(
    defaultHighPriorityOnly,
  );
  const [currentPage, setCurrentPage] = useState(1);
  const [sortConfig, setSortConfig] = useState({
    key: "detectionTime",
    direction: "desc",
  });
  const [totalPages, setTotalPages] = useState(1);
  const [totalRecords, setTotalRecords] = useState(0);
  const [severityOptions, setSeverityOptions] = useState([]);
  const effectiveHighPriorityOnly = lockHighPriority || highPriorityOnly;

  useEffect(() => {
    const loadFilters = async () => {
      try {
        const res = await apiClient.get(FILTERS_URL);
        if (!res.ok) return;
        const json = await res.json();
        setSeverityOptions(
          Array.isArray(json?.severities) ? json.severities : [],
        );
      } catch {
        // keep default empty options
      }
    };
    loadFilters();
  }, []);

  // Click outside handler for popovers
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (popoverRef.current && !popoverRef.current.contains(event.target)) {
        setOpenFilterPopover(null);
        setLocalFilters(appliedFilters);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [appliedFilters]);

  const applyFilter = () => {
    setAppliedFilters({ ...localFilters });
    setOpenFilterPopover(null);
    setCurrentPage(1);
  };

  const clearFilter = (key) => {
    if (key === "date") {
      setLocalFilters((prev) => ({ ...prev, startDate: "", endDate: "" }));
      setAppliedFilters((prev) => ({ ...prev, startDate: "", endDate: "" }));
    } else {
      const resetVal =
        key === "cvss"
          ? { min: 0, max: 10 }
          : key === "severity" || key === "status"
            ? "all"
            : "";
      setLocalFilters((prev) => ({ ...prev, [key]: resetVal }));
      setAppliedFilters((prev) => ({ ...prev, [key]: resetVal }));
    }
    setOpenFilterPopover(null);
    setCurrentPage(1);
  };

  const clearAllFilters = () => {
    setLocalFilters(defaultFilters);
    setAppliedFilters(defaultFilters);
    setOpenFilterPopover(null);
    setCurrentPage(1);
  };

  const fetchVulnerabilities = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const params = new URLSearchParams();
      params.set("page", String(currentPage - 1));
      params.set("size", String(PAGE_SIZE));

      if (appliedFilters.severity !== "all") {
        params.set("severity", appliedFilters.severity);
      }
      if (appliedFilters.status !== "all") {
        params.set("status", appliedFilters.status);
      }
      if (appliedFilters.startDate) {
        params.set("startDate", appliedFilters.startDate);
      }
      if (appliedFilters.endDate) {
        params.set("endDate", appliedFilters.endDate);
      }
      if (appliedFilters.cvss.min > 0) {
        params.set("minCvss", String(appliedFilters.cvss.min));
      }
      if (appliedFilters.cvss.max < 10) {
        params.set("maxCvss", String(appliedFilters.cvss.max));
      }
      if (appliedFilters.agentName) {
        params.set("agentName", appliedFilters.agentName);
      }
      if (appliedFilters.agentGroup) {
        params.set("agentGroup", appliedFilters.agentGroup);
      }
      if (appliedFilters.cve) {
        params.set("cve", appliedFilters.cve);
      }
      if (appliedFilters.package) {
        params.set("packageName", appliedFilters.package);
      }
      if (effectiveHighPriorityOnly) {
        params.set("severity", "Critical");
      }

      const response = await apiClient.get(`${API_URL}?${params.toString()}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      const content = Array.isArray(data)
        ? data
        : data && Array.isArray(data.content)
          ? data.content
          : [];

      setRows(Array.isArray(content) ? content : []);
      setTotalPages(typeof data?.totalPages === "number" ? data.totalPages : 1);
      setTotalRecords(
        typeof data?.totalElements === "number"
          ? data.totalElements
          : Array.isArray(content)
            ? content.length
            : 0,
      );
    } catch (fetchError) {
      console.error("Error al obtener vulnerabilidades:", fetchError);
      setError("No se pudo cargar la tabla de activos desde el backend.");
    } finally {
      setLoading(false);
    }
  }, [
    appliedFilters,
    currentPage,
    effectiveHighPriorityOnly,
  ]);

  useEffect(() => {
    fetchVulnerabilities();
  }, [fetchVulnerabilities]);

  const handleSort = (key) => {
    const defaultDirection =
      key === "id" || key === "cvss3Score" || key === "detectionTime"
        ? "desc"
        : "asc";
    setSortConfig((previousSort) => {
      if (previousSort.key === key) {
        return {
          key,
          direction: previousSort.direction === "asc" ? "desc" : "asc",
        };
      }
      return { key, direction: defaultDirection };
    });
    setCurrentPage(1);
  };

  const getSortIndicator = (key) => {
    if (sortConfig.key !== key) return "↕";
    return sortConfig.direction === "asc" ? "↑" : "↓";
  };

  const isFilterActive = (filterKey) => {
    if (filterKey === "cvss")
      return appliedFilters.cvss.min > 0 || appliedFilters.cvss.max < 10;
    if (filterKey === "date")
      return !!appliedFilters.startDate || !!appliedFilters.endDate;
    return (
      appliedFilters[filterKey] &&
      appliedFilters[filterKey] !== "all" &&
      appliedFilters[filterKey] !== ""
    );
  };

  const renderFilterPopover = (sortKey, filterKey, title, children) => (
    <th className="sortable th-with-filter">
      <div
        className="th-content"
        ref={openFilterPopover === filterKey ? popoverRef : null}
      >
        <div className="th-content-header">
          <button
            type="button"
            className={`sort-header-btn ${sortConfig.key === sortKey ? "active" : ""}`}
            onClick={() => handleSort(sortKey)}
          >
            <span>{title}</span>
            <span className="sort-indicator">{getSortIndicator(sortKey)}</span>
          </button>
          <button
            className={`filter-icon-btn ${isFilterActive(filterKey) ? "active" : ""}`}
            onClick={(e) => {
              e.stopPropagation();
              setOpenFilterPopover(
                openFilterPopover === filterKey ? null : filterKey,
              );
            }}
          >
            <Filter size={14} />
          </button>
        </div>
        {openFilterPopover === filterKey && (
          <div className="filter-popover" onClick={(e) => e.stopPropagation()}>
            {children}
            <div className="filter-popover-actions">
              <button
                type="button"
                className="btn-clear"
                onClick={() => clearFilter(filterKey)}
              >
                Limpiar
              </button>
              <button type="button" className="btn-apply" onClick={applyFilter}>
                Aplicar
              </button>
            </div>
          </div>
        )}
      </div>
    </th>
  );

  const paginatedRows = rows;

  return (
    <div className="tables-container">
      <main className="tables-content">
        <header className="tables-header">
          <div>
            <h1>{title}</h1>
            <p>{subtitle}</p>
          </div>
          <div className="tables-header-actions">
            {!lockHighPriority && (
              <button
                className={`priority-toggle ${effectiveHighPriorityOnly ? "active" : ""}`}
                onClick={() =>
                  setHighPriorityOnly((previousValue) => !previousValue)
                }
              >
                Alta prioridad {effectiveHighPriorityOnly ? "ON" : "OFF"}
              </button>
            )}
            <button
              className="refresh-button"
              onClick={fetchVulnerabilities}
              disabled={loading}
            >
              <RefreshCcw size={16} />
              {loading ? "Actualizando..." : "Actualizar"}
            </button>
          </div>
        </header>

        <div className="tables-header-actions">
          <button className="refresh-button" onClick={clearAllFilters}>Limpiar filtros de esta vista</button>
        </div>

        {/* Línea de tiempo — refleja los filtros activos de la tabla */}
        <TimelinePanel
          search={appliedFilters.search}
          cve={appliedFilters.cve || ''}
          severity={appliedFilters.severity !== 'all' ? appliedFilters.severity : ''}
          agentId={appliedFilters.agent || ''}
          highPriorityOnly={effectiveHighPriorityOnly}
          minCvss={appliedFilters.cvss.min}
          maxCvss={appliedFilters.cvss.max}
          packageName={appliedFilters.package || ''}
          status={appliedFilters.status || ''}
          startDate={appliedFilters.startDate || ''}
          endDate={appliedFilters.endDate || ''}
        />

        {error && (
          <div className="tables-error">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        <section className="tables-card">
          <div className="tables-wrapper">
            <table className="assets-table">
              <thead>
                <tr>
                  <th>ID</th>

                  {renderFilterPopover(
                    "agentId",
                    "agentName",
                    "Nombre de agente",
                    <input
                      type="text"
                      className="inline-filter-input"
                      placeholder="Nombre exacto del agente"
                      value={localFilters.agentName}
                      onChange={(e) =>
                        setLocalFilters({
                          ...localFilters,
                          agentName: e.target.value,
                        })
                      }
                    />,
                  )}

                  {renderFilterPopover(
                    "cve",
                    "cve",
                    "CVE",
                    <input
                      type="text"
                      className="inline-filter-input"
                      placeholder="Filtrar por CVE"
                      value={localFilters.cve}
                      onChange={(e) =>
                        setLocalFilters({
                          ...localFilters,
                          cve: e.target.value,
                        })
                      }
                    />,
                  )}

                  {hideSeverityFilter ? (
                    <th className="sortable">
                      <button
                        type="button"
                        className={`sort-header-btn ${sortConfig.key === "severity" ? "active" : ""}`}
                        onClick={() => handleSort("severity")}
                      >
                        <span>Severidad</span>
                        <span className="sort-indicator">
                          {getSortIndicator("severity")}
                        </span>
                      </button>
                    </th>
                  ) : (
                    renderFilterPopover(
                      "severity",
                      "severity",
                      "Severidad",
                      <select
                        className="inline-filter-select"
                        value={localFilters.severity}
                        onChange={(e) =>
                          setLocalFilters({
                            ...localFilters,
                            severity: e.target.value,
                          })
                        }
                      >
                        <option value="all">Todas</option>
                        {severityOptions.map((sev) => (
                          <option key={sev} value={sev}>
                            {sev}
                          </option>
                        ))}
                      </select>,
                    )
                  )}

                  {renderFilterPopover(
                    "cvss3Score",
                    "cvss",
                    "CVSS",
                    <div className="inline-cvss-filter">
                      <div className="mui-slider-container dual-slider-container">
                        <div
                          className="dual-slider-track"
                          style={{
                            left: `${(localFilters.cvss.min / 10) * 100}%`,
                            right: `${100 - (localFilters.cvss.max / 10) * 100}%`,
                          }}
                        ></div>
                        <input
                          type="range"
                          className="mui-slider dual-slider-input"
                          min="0"
                          max="10"
                          step="0.1"
                          value={localFilters.cvss.min}
                          onChange={(e) =>
                            setLocalFilters({
                              ...localFilters,
                              cvss: {
                                ...localFilters.cvss,
                                min: Math.min(
                                  parseFloat(e.target.value),
                                  localFilters.cvss.max - 0.1,
                                ),
                              },
                            })
                          }
                        />
                        <input
                          type="range"
                          className="mui-slider dual-slider-input"
                          min="0"
                          max="10"
                          step="0.1"
                          value={localFilters.cvss.max}
                          onChange={(e) =>
                            setLocalFilters({
                              ...localFilters,
                              cvss: {
                                ...localFilters.cvss,
                                max: Math.max(
                                  parseFloat(e.target.value),
                                  localFilters.cvss.min + 0.1,
                                ),
                              },
                            })
                          }
                        />
                      </div>
                      <span className="cvss-value">
                        {localFilters.cvss.min} - {localFilters.cvss.max}
                      </span>
                    </div>,
                  )}

                  {renderFilterPopover(
                    "packageName",
                    "package",
                    "Paquete",
                    <input
                      type="text"
                      className="inline-filter-input"
                      placeholder="Filtrar por Paquete"
                      value={localFilters.package}
                      onChange={(e) =>
                        setLocalFilters({
                          ...localFilters,
                          package: e.target.value,
                        })
                      }
                    />,
                  )}

                  {renderFilterPopover(
                    "status",
                    "status",
                    "Estado",
                    <select
                      className="inline-filter-select"
                      value={localFilters.status}
                      onChange={(e) =>
                        setLocalFilters({
                          ...localFilters,
                          status: e.target.value,
                        })
                      }
                    >
                      <option value="all">Todos</option>
                      <option value="active">Active</option>
                      <option value="resolved">Resolved</option>
                    </select>,
                  )}

                  {renderFilterPopover(
                    "detectionTime",
                    "date",
                    "Detectada",
                    <div
                      className="date-popover-content"
                      style={{
                        position: "static",
                        boxShadow: "none",
                        border: "none",
                        padding: "0",
                        minWidth: "180px",
                      }}
                    >
                      <label>
                        <span>Desde:</span>
                        <input
                          type="date"
                          className="inline-date-input"
                          value={localFilters.startDate}
                          onChange={(e) =>
                            setLocalFilters({
                              ...localFilters,
                              startDate: e.target.value,
                            })
                          }
                        />
                      </label>
                      <label>
                        <span>Hasta:</span>
                        <input
                          type="date"
                          className="inline-date-input"
                          value={localFilters.endDate}
                          onChange={(e) =>
                            setLocalFilters({
                              ...localFilters,
                              endDate: e.target.value,
                            })
                          }
                        />
                      </label>
                    </div>,
                  )}

                  <th>Descripción</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td
                      colSpan="9"
                      className="tables-state"
                      style={{ textAlign: "center" }}
                    >
                      Cargando datos...
                    </td>
                  </tr>
                ) : paginatedRows.length === 0 ? (
                  <tr>
                    <td
                      colSpan="9"
                      className="tables-state"
                      style={{ textAlign: "center" }}
                    >
                      No se encontraron registros con esos filtros.
                    </td>
                  </tr>
                ) : (
                  <>
                    {paginatedRows.map((row) => (
                      <tr key={row.id}>
                        <td>{row.id}</td>
                        <td>{row.agentId || "-"}</td>
                        <td>{row.cve || "-"}</td>
                        <td>{row.severity || "-"}</td>
                        <td>{row.cvss3Score ?? "-"}</td>
                        <td>
                          {`${row.packageName || "-"} ${row.packageVersion ? `(${row.packageVersion})` : ""}`.trim()}
                        </td>
                        <td>{row.status || "-"}</td>
                        <td>{formatDate(row.detectionTime)}</td>
                        <td title={row.description || ""}>
                          {truncateText(row.description)}
                        </td>
                      </tr>
                    ))}
                  </>
                )}
              </tbody>
            </table>
          </div>
          <footer className="tables-footer">
            <span>
              Mostrando {paginatedRows.length} de {totalRecords} registros
            </span>
            <div className="pagination-controls">
              <button
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1 || loading}
                className="page-btn"
              >
                Anterior
              </button>
              <span className="page-info">
                Página {currentPage} de {totalPages || 1}
              </span>
              <button
                onClick={() =>
                  setCurrentPage((p) => Math.min(totalPages, p + 1))
                }
                disabled={
                  currentPage === totalPages || totalPages === 0 || loading
                }
                className="page-btn"
              >
                Siguiente
              </button>
            </div>
          </footer>
        </section>
      </main>
    </div>
  );
};

export default Tables;
