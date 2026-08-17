export const CHART_COLORS = [
    '#5B8CFF',
    '#34D399',
    '#F59E0B',
    '#F97316',
    '#A78BFA',
    '#22D3EE',
    '#F472B6',
    '#2DD4BF',
    '#FB7185',
];

export const EMPTY_STATS = {
    total: 0,
    category: [],
    severity: [],
    cve: [],
    package: [],
    agent: [],
};

export const normalizeText = (value, fallback = 'Sin dato') => {
    if (value === null || value === undefined) return fallback;
    const normalized = String(value).trim();
    return normalized.length > 0 ? normalized : fallback;
};

export const sanitizeChartItems = (items) => {
    if (!Array.isArray(items)) {
        return [];
    }

    return items
        .map((item) => {
            const name = normalizeText(item?.name);
            const parsedValue = Number(item?.value);
            const value = Number.isFinite(parsedValue) && parsedValue > 0 ? parsedValue : 0;

            return { name, value };
        })
        .filter((item) => item.value > 0);
};

export const sanitizeStatsPayload = (payload) => {
    const parsedTotal = Number(payload?.total);

    return {
        total: Number.isFinite(parsedTotal) && parsedTotal > 0 ? parsedTotal : 0,
        category: sanitizeChartItems(payload?.category),
        severity: sanitizeChartItems(payload?.severity),
        cve: sanitizeChartItems(payload?.cve),
        package: sanitizeChartItems(payload?.package),
        agent: sanitizeChartItems(payload?.agent),
    };
};
