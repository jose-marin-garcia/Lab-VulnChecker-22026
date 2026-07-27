import { useCallback, useEffect, useRef, useState } from "react";
import { apiClient } from "../../config/auth";
import "./TimelinePanel.css";

const API_BASE_URL = import.meta.env.VITE_API_URL;
const TIMELINE_URL = `${API_BASE_URL}/api/snapshots/timeline`;

const SEVERITY_COLORS = {
  critical: "#ff4757",
  high: "#ff6b35",
  medium: "#ffa502",
  low: "#2ed573",
  default: "#a4b0be",
};

/** Deduplica vulns por cve+agentId para no repetir la misma entrada en el popover. */
function dedupeVulns(vulns) {
  const seen = new Set();
  return vulns.filter((v) => {
    const key = `${v.cve}|${v.agentName}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function severityColor(severity) {
  if (!severity) return SEVERITY_COLORS.default;
  return SEVERITY_COLORS[severity.toLowerCase()] ?? SEVERITY_COLORS.default;
}

const TimelinePanel = ({
  search = "",
  cve = "",
  severity = "",
  agentName = "",
  highPriorityOnly = false,
  minCvss = 0,
  maxCvss = 10,
  packageName = "",
  status = "",
  startDate = "",
  endDate = "",
}) => {
  const [points, setPoints] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const debounceRef = useRef(null);
  const popoverRef = useRef(null);

  const fetchTimeline = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("months", "12");
      if (cve?.trim()) params.set("cve", cve.trim());
      if (severity?.trim()) params.set("severity", severity.trim());
      if (agentName?.trim()) params.set("agentName", agentName.trim());
      if (highPriorityOnly) params.set("highPriorityOnly", "true");
      if (search?.trim()) params.set("search", search.trim());
      if (minCvss > 0) params.set("minCvss", String(minCvss));
      if (maxCvss < 10) params.set("maxCvss", String(maxCvss));
      if (packageName?.trim()) params.set("packageName", packageName.trim());
      if (status?.trim() && status !== "all")
        params.set("status", status.trim());
      if (startDate?.trim()) params.set("startDate", startDate.trim());
      if (endDate?.trim()) params.set("endDate", endDate.trim());

      const res = await apiClient.get(`${TIMELINE_URL}?${params.toString()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setPoints(Array.isArray(data) ? data : []);
    } catch {
      setPoints([]);
    } finally {
      setLoading(false);
    }
  }, [
    cve,
    severity,
    agentName,
    highPriorityOnly,
    search,
    minCvss,
    maxCvss,
    packageName,
    status,
    startDate,
    endDate,
  ]);

  // Debounce al cambiar filtros para no spamear el API
  useEffect(() => {
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(fetchTimeline, 400);
    return () => clearTimeout(debounceRef.current);
  }, [fetchTimeline]);

  // Cerrar popover al hacer click fuera
  useEffect(() => {
    const handler = (e) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target)) {
        setHoveredIndex(null);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const maxCount = points.reduce(
    (m, p) => Math.max(m, p.newCount, p.resolvedCount),
    1,
  );

  if (loading) {
    return (
      <div className="tl-panel tl-panel--loading">
        <span className="tl-loading-dot" />
        <span className="tl-loading-dot" />
        <span className="tl-loading-dot" />
      </div>
    );
  }

  if (points.length === 0) {
    return (
      <div className="tl-panel tl-panel--empty">
        <p>
          Sin datos de sincronización aún. Realiza una sincronización desde
          Wazuh para ver la línea de tiempo.
        </p>
      </div>
    );
  }

  return (
    <div className="tl-panel">
      <div className="tl-header">
        <span className="tl-title">Línea de Tiempo</span>
        <div className="tl-legend">
          <span className="tl-legend-dot tl-legend-new" />
          <span>Nuevas</span>
          <span className="tl-legend-dot tl-legend-resolved" />
          <span>Resueltas</span>
        </div>
      </div>

      <div
        className="tl-track-wrapper"
        ref={hoveredIndex !== null ? popoverRef : null}
      >
        {/* SVG línea de fondo */}
        <svg className="tl-line-svg" aria-hidden="true">
          <line x1="0" y1="50%" x2="100%" y2="50%" className="tl-line" />
        </svg>

        <div className="tl-points">
          {points.map((point, idx) => {
            const newPct = Math.round((point.newCount / maxCount) * 100);
            const resolvedPct = Math.round(
              (point.resolvedCount / maxCount) * 100,
            );
            const isActive = hoveredIndex === idx;
            const hasActivity = point.newCount > 0 || point.resolvedCount > 0;

            return (
              <div
                key={point.syncDate}
                className={`tl-point-wrapper ${isActive ? "tl-point-wrapper--active" : ""}`}
              >
                {/* Barras sobre y bajo la línea */}
                <div className="tl-bars">
                  <div
                    className="tl-bar tl-bar--new"
                    style={{
                      height: `${Math.max(newPct * 0.4, point.newCount > 0 ? 4 : 0)}px`,
                    }}
                    title={`${point.newCount} nuevas`}
                  />
                  <div
                    className="tl-bar tl-bar--resolved"
                    style={{
                      height: `${Math.max(resolvedPct * 0.4, point.resolvedCount > 0 ? 4 : 0)}px`,
                    }}
                    title={`${point.resolvedCount} resueltas`}
                  />
                </div>

                {/* Punto interactivo */}
                <button
                  type="button"
                  className={`tl-dot ${hasActivity ? "tl-dot--active" : ""} ${isActive ? "tl-dot--hovered" : ""}`}
                  onClick={() => setHoveredIndex(isActive ? null : idx)}
                  aria-label={`Sync ${point.label}: ${point.newCount} nuevas, ${point.resolvedCount} resueltas`}
                >
                  {hasActivity && <span className="tl-dot-pulse" />}
                </button>

                {/* Fecha */}
                <span className="tl-date-label">{point.label}</span>

                {/* Contadores pequeños */}
                {hasActivity && (
                  <div className="tl-mini-counts">
                    {point.newCount > 0 && (
                      <span className="tl-mini-new">+{point.newCount}</span>
                    )}
                    {point.resolvedCount > 0 && (
                      <span className="tl-mini-resolved">
                        -{point.resolvedCount}
                      </span>
                    )}
                  </div>
                )}

                {/* Popover al hacer hover/click */}
                {isActive && (
                  <div
                    className="tl-popover"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="tl-popover-header">
                      <strong>{point.label}</strong>
                      <button
                        type="button"
                        className="tl-popover-close"
                        onClick={() => setHoveredIndex(null)}
                      >
                        ✕
                      </button>
                    </div>

                    <div className="tl-popover-columns">
                      {/* Columna NUEVAS */}
                      <div className="tl-popover-col">
                        <div className="tl-popover-col-title tl-popover-col-title--new">
                          ↑ Nuevas ({point.newCount})
                        </div>
                        {point.newVulns.length === 0 ? (
                          <span className="tl-popover-empty">Sin datos</span>
                        ) : (
                          <ul className="tl-popover-list">
                            {dedupeVulns(point.newVulns).map((v, i) => (
                              <li key={`new-${i}`} className="tl-popover-item">
                                <span
                                  className="tl-sev-dot"
                                  style={{
                                    background: severityColor(v.severity),
                                  }}
                                />
                                <span className="tl-cve">{v.cve}</span>
                                <span className="tl-agent">({v.agentName})</span>
                              </li>
                            ))}
                            {point.newCount > point.newVulns.length && (
                              <li className="tl-popover-more">
                                +{point.newCount - point.newVulns.length} más
                              </li>
                            )}
                          </ul>
                        )}
                      </div>

                      {/* Columna RESUELTAS */}
                      <div className="tl-popover-col">
                        <div className="tl-popover-col-title tl-popover-col-title--resolved">
                          ↓ Resueltas ({point.resolvedCount})
                        </div>
                        {point.resolvedVulns.length === 0 ? (
                          <span className="tl-popover-empty">Sin datos</span>
                        ) : (
                          <ul className="tl-popover-list">
                            {dedupeVulns(point.resolvedVulns).map((v, i) => (
                              <li key={`res-${i}`} className="tl-popover-item">
                                <span
                                  className="tl-sev-dot"
                                  style={{
                                    background: severityColor(v.severity),
                                  }}
                                />
                                <span className="tl-cve">{v.cve}</span>
                                <span className="tl-agent">({v.agentName})</span>
                              </li>
                            ))}
                            {point.resolvedCount >
                              point.resolvedVulns.length && (
                              <li className="tl-popover-more">
                                +
                                {point.resolvedCount -
                                  point.resolvedVulns.length}{" "}
                                más
                              </li>
                            )}
                          </ul>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default TimelinePanel;
