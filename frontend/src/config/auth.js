function getToken() {
    return localStorage.getItem('token');
}

function authHeader() {
    const token = getToken();
    return token ? { 'Authorization': `Bearer ${token}` } : {};
}

export function getAuthHeaders() {
    return authHeader();
}

export async function authFetch(url, options = {}) {
    const headers = {
        ...authHeader(),
        ...options.headers,
    };
    return fetch(url, { ...options, headers });
}

export const apiClient = {
    async get(url) {
        return fetch(url, { headers: authHeader() });
    },

    async post(url, body) {
        return fetch(url, {
            method: 'POST',
            headers: {
                ...authHeader(),
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
        });
    },

    async put(url, body) {
        return fetch(url, {
            method: 'PUT',
            headers: {
                ...authHeader(),
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
        });
    },

    async patch(url, body) {
        const options = { method: 'PATCH', headers: authHeader() };
        if (body !== undefined) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }
        return fetch(url, options);
    },

    async delete(url) {
        return fetch(url, { method: 'DELETE', headers: authHeader() });
    },
};
