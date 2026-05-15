import React, { useCallback, useEffect, useState, useRef } from "react";
import {
  AlertCircle,
  RefreshCcw,
  Search,
  Filter,
  Download,
} from "lucide-react";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { buildApiUrl } from "../../config/api";
import { apiClient } from "../../config/auth";
import "../Tables/Tables.css";
import "./Summary.css";

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

const Summary = ({
  title = "Resumen de Vulnerabilidades",
  subtitle = "Vista y resumen de las vulnerabilidades activas.",
  defaultHighPriorityOnly = false,
  lockHighPriority = false,
  hideSeverityFilter = false,
}) => {
  const defaultFilters = {
    search: "",
    severity: "all",
    agent: "",
    cve: "",
    description: "",
    startDate: "",
    endDate: "",
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
  const [pageInput, setPageInput] = useState("");
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
        /* keep defaults */
      }
    };
    loadFilters();
  }, []);

  // Click outside handler
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
      const resetVal = key === "severity" ? "all" : "";
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

  const applyGlobalSearch = () => {
    setAppliedFilters((prev) => ({ ...prev, search: localFilters.search }));
    setCurrentPage(1);
  };

  const fetchVulnerabilities = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      params.set("page", String(currentPage - 1));
      params.set("size", String(PAGE_SIZE));
      params.set("sortKey", sortConfig.key);
      params.set("sortDir", sortConfig.direction);

      if (appliedFilters.severity !== "all")
        params.set("severity", appliedFilters.severity);
      if (appliedFilters.agent) params.set("agentId", appliedFilters.agent);
      if (appliedFilters.cve) params.set("cve", appliedFilters.cve);
      if (appliedFilters.description)
        params.set("description", appliedFilters.description);
      if (appliedFilters.startDate)
        params.set("startDate", appliedFilters.startDate);
      if (appliedFilters.endDate) params.set("endDate", appliedFilters.endDate);
      if (appliedFilters.search.trim())
        params.set("search", appliedFilters.search.trim());
      if (effectiveHighPriorityOnly) params.set("highPriorityOnly", "true");

      const response = await apiClient.get(`${API_URL}?${params.toString()}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const data = await response.json();
      const content = data.content || (Array.isArray(data) ? data : []);

      setRows(content);
      setTotalPages(data.totalPages || 1);
      setTotalRecords(data.totalElements || content.length);
    } catch (err) {
      setError("No se pudo cargar la tabla desde el backend.");
    } finally {
      setLoading(false);
    }
  }, [currentPage, appliedFilters, effectiveHighPriorityOnly, sortConfig]);

  useEffect(() => {
    fetchVulnerabilities();
  }, [fetchVulnerabilities]);

  const handleSort = (key) => {
    setSortConfig((prev) => ({
      key,
      direction: prev.key === key && prev.direction === "asc" ? "desc" : "asc",
    }));
    setCurrentPage(1);
  };

  const getSortIndicator = (key) => {
    if (sortConfig.key !== key) return "↕";
    return sortConfig.direction === "asc" ? "↑" : "↓";
  };

  const isFilterActive = (filterKey) => {
    if (filterKey === "date")
      return !!appliedFilters.startDate || !!appliedFilters.endDate;
    if (filterKey === "severity") return appliedFilters.severity !== "all";
    return !!appliedFilters[filterKey];
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

  // PDF generation
  const calculateSHA256 = async (arrayBuffer) => {
    const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  const generateSecurePDF = async () => {
    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text("Reporte de Vulnerabilidades - VulnChecker", 14, 20);

    const tableData = rows.map((row) => [
      row.cve || "-",
      row.agentId || "-",
      row.severity || "-",
      row.description || "-",
      formatDate(row.detectionTime),
    ]);

    autoTable(doc, {
      startY: 45,
      head: [["CVE ID", "Agente", "Severidad", "Descripción", "Detectado el"]],
      body: tableData,
      headStyles: { fillColor: [32, 32, 32] },
      styles: { fontSize: 8 },
      columnStyles: { 3: { cellWidth: 80 } },
    });

    const pdfBuffer = doc.output("arraybuffer");
    const pdfHash = await calculateSHA256(pdfBuffer);

    try {
      const response = await apiClient.post(`${API_BASE_URL}/api/reports/sign`, {
        reportName: `vuln_report_${Date.now()}.pdf`,
        sha256Hash: pdfHash,
      });
      if (response.ok) {
        doc.save(`vuln_report_${Date.now()}.pdf`);
        alert("Reporte generado y firmado con éxito.");
      } else {
        alert("Error al firmar el documento.");
      }
    } catch (error) {
      console.error("Error conectando al backend:", error);
    }
  };

  return (
    <div className="tables-container">
      <main className="tables-content">
        <header className="tables-header">
          <div>
            <h1>{title}</h1>
            <p>{subtitle}</p>
          </div>
          <div className="tables-header-actions">
            <button
              className="refresh-button"
              onClick={generateSecurePDF}
              disabled={rows.length === 0}
            >
              <Download size={16} /> Exportar PDF
            </button>
            {!lockHighPriority && (
              <button
                className={`priority-toggle ${effectiveHighPriorityOnly ? "active" : ""}`}
                onClick={() => setHighPriorityOnly((prev) => !prev)}
              >
                Alta prioridad {effectiveHighPriorityOnly ? "ON" : "OFF"}
              </button>
            )}
            <button
              className="refresh-button"
              onClick={fetchVulnerabilities}
              disabled={loading}
            >
              <RefreshCcw size={16} className={loading ? "animate-spin" : ""} />
              {loading ? "Actualizando..." : "Actualizar"}
            </button>
          </div>
        </header>

        <section
          className="tables-filters"
          style={{ gridTemplateColumns: "minmax(280px, 1fr) auto auto" }}
        >
          <label className="search-input-wrapper">
            <Search size={16} />
            <input
              type="text"
              placeholder="Búsqueda global..."
              value={localFilters.search}
              onChange={(e) =>
                setLocalFilters({ ...localFilters, search: e.target.value })
              }
              onKeyDown={(e) => e.key === "Enter" && applyGlobalSearch()}
            />
          </label>
          <button
            className="refresh-button"
            onClick={applyGlobalSearch}
            style={{ width: "fit-content", padding: "0 1rem" }}
          >
            Buscar
          </button>
          <button
            className="refresh-button"
            onClick={clearAllFilters}
            style={{
              width: "fit-content",
              padding: "0 1rem",
              backgroundColor: "transparent",
              border: "1px solid #ff6b6b",
              color: "#ff6b6b",
            }}
          >
            Limpiar Todos
          </button>
        </section>

        {error && (
          <div className="tables-error">
            <AlertCircle size={18} /> <span>{error}</span>
          </div>
        )}

        <section className="tables-card">
          <div className="tables-wrapper">
            <table className="assets-table">
              <thead>
                <tr>
                  {renderFilterPopover(
                    "cve",
                    "cve",
                    "CVE ID",
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

                  {renderFilterPopover(
                    "agentId",
                    "agent",
                    "Agente",
                    <input
                      type="text"
                      className="inline-filter-input"
                      placeholder="Filtrar por Agente"
                      value={localFilters.agent}
                      onChange={(e) =>
                        setLocalFilters({
                          ...localFilters,
                          agent: e.target.value,
                        })
                      }
                    />,
                  )}

                  {hideSeverityFilter ? (
                    <th className="sortable">
                      <button
                        type="button"
                        className="sort-header-btn"
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
                    "detectionTime",
                    "date",
                    "Detectada",
                    <>
                      <label className="popover-label">
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
                      <label className="popover-label">
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
                    </>,
                  )}
                  {renderFilterPopover(
                    "description",
                    "description",
                    "Descripción",
                    <input
                      type="text"
                      className="inline-filter-input"
                      placeholder="Palabra clave..."
                      value={localFilters.description}
                      onChange={(e) =>
                        setLocalFilters({
                          ...localFilters,
                          description: e.target.value,
                        })
                      }
                    />,
                  )}
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td
                      colSpan="5"
                      className="tables-state"
                      style={{ textAlign: "center" }}
                    >
                      Cargando datos...
                    </td>
                  </tr>
                ) : rows.length === 0 ? (
                  <tr>
                    <td
                      colSpan="5"
                      className="tables-state"
                      style={{ textAlign: "center" }}
                    >
                      No se encontraron registros con esos filtros.
                    </td>
                  </tr>
                ) : (
                  rows.map((row) => (
                    <tr key={row.id}>
                      <td>{row.cve || "-"}</td>
                      <td>{row.agentId || "-"}</td>
                      <td>{row.severity || "-"}</td>
                      <td>{formatDate(row.detectionTime)}</td>
                      <td title={row.description}>
                        {truncateText(row.description)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <footer className="tables-footer">
            <span>
              Mostrando {rows.length} de {totalRecords}
            </span>
            <div className="pagination-controls">
              <button
                onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
                disabled={currentPage === 1}
                className="page-btn"
              >
                Anterior
              </button>
              <span className="page-info">
                Página {currentPage} de {totalPages}
              </span>
              <button
                onClick={() =>
                  setCurrentPage((p) => Math.min(p + 1, totalPages))
                }
                disabled={currentPage === totalPages}
                className="page-btn"
              >
                Siguiente
              </button>
              <label className="pagination-go">
                <span>Ir a</span>
                <input
                  type="number"
                  value={pageInput}
                  onChange={(e) => setPageInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      const n = parseInt(pageInput, 10);
                      if (!isNaN(n))
                        setCurrentPage(Math.max(1, Math.min(n, totalPages)));
                      setPageInput("");
                    }
                  }}
                />
                <button
                  type="button"
                  onClick={() => {
                    const n = parseInt(pageInput, 10);
                    if (!Number.isNaN(n))
                      setCurrentPage(Math.max(1, Math.min(n, totalPages)));
                    setPageInput("");
                  }}
                >
                  Ir
                </button>
              </label>
            </div>
          </footer>
        </section>
      </main>
    </div>
  );
};

export default Summary;
