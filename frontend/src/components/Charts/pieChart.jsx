import { useMemo, useState } from 'react';
import {
    Cell,
    Pie,
    PieChart,
    ResponsiveContainer,
    Tooltip,
} from 'recharts';
import { CHART_COLORS, normalizeText } from './pieChart';

const PieTooltip = ({ active, payload, total }) => {
    if (!active || !Array.isArray(payload) || payload.length === 0) return null;

    const item = payload[0];
    const label = normalizeText(item?.name);
    const value = Number(item?.value) || 0;
    const percentage = total === 0 ? 0 : (value / total) * 100;

    return (
        <div className="pie-tooltip-box">
            <div className="pie-tooltip-label">{label}</div>
            <div className="pie-tooltip-value">
                Cantidad: <strong>{value}</strong> ({percentage.toFixed(1)}%)
            </div>
        </div>
    );
};

export const PieCard = ({ title, data, wide = false }) => {
    const total = useMemo(() => data.reduce((sum, entry) => sum + entry.value, 0), [data]);
    const [activeIndex, setActiveIndex] = useState(-1);

    return (
        <article className={`pie-card ${wide ? 'wide' : ''}`}>
            <header className="pie-card-header">
                <h2>{title}</h2>
                <span>Total: {total}</span>
            </header>

            {data.length === 0 ? (
                <div className="pie-empty">No hay datos para mostrar.</div>
            ) : (
                <div className="pie-plot">
                    <div className="pie-canvas">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
                                <Pie
                                    data={data}
                                    dataKey="value"
                                    nameKey="name"
                                    cx="50%"
                                    cy="50%"
                                    outerRadius={95}
                                    innerRadius={55}
                                    onMouseEnter={(_, index) => setActiveIndex(index)}
                                    onMouseLeave={() => setActiveIndex(-1)}
                                >
                                    {data.map((entry, index) => (
                                        <Cell
                                            key={`${title}-${entry.name}`}
                                            fill={CHART_COLORS[index % CHART_COLORS.length]}
                                            stroke={index === activeIndex ? '#f8fafc' : '#1f2937'}
                                            strokeWidth={index === activeIndex ? 2.2 : 1}
                                            opacity={activeIndex === -1 || index === activeIndex ? 1 : 0.65}
                                        />
                                    ))}
                                </Pie>
                                <Tooltip
                                    content={<PieTooltip total={total} />}
                                    offset={24}
                                    wrapperStyle={{ zIndex: 50 }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                        <div className="pie-center-metric">
                            <span>Total</span>
                            <strong>{total}</strong>
                        </div>
                    </div>
                    <ul className="pie-legend-list">
                        {data.map((entry, index) => (
                            <li key={`${title}-legend-${entry.name}`} className="pie-legend-item">
                                <span
                                    className="pie-legend-dot"
                                    style={{ backgroundColor: CHART_COLORS[index % CHART_COLORS.length] }}
                                />
                                <span className="pie-legend-label">{entry.name}</span>
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </article>
    );
};
