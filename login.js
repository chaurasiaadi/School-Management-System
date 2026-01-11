const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors()); // Allow cross-origin requests (if HTML served separately)
app.use(bodyParser.json());
app.use(express.static('public')); // Serve your HTML if needed from 'public' folder

// Mock database for students and staff
const users = {
    student: [
        { id: 'stu001', email: 'student1@example.com', password: '123456' },
        { id: 'stu002', email: 'student2@example.com', password: 'abcdef' },
    ],
    staff: [
        { id: 'staff001', email: 'staff1@example.com', password: '123456' },
        { id: 'staff002', email: 'staff2@example.com', password: 'abcdef' },
    ]
};

// API: Login
app.post('/api/login', (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ success: false, message: 'Missing credentials.' });
    }

    const roleUsers = users[role] || [];
    const user = roleUsers.find(u => u.id === username || u.email === username);

    if (!user || user.password !== password) {
        return res.json({ success: false, message: 'Invalid username or password.' });
    }

    return res.json({ success: true, message: `${role} login successful!`, user: { id: user.id, email: user.email } });
});

// API: Register (optional)
app.post('/api/register', (req, res) => {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password || !role) {
        return res.status(400).json({ success: false, message: 'Missing registration fields.' });
    }

    const roleUsers = users[role] || [];
    const exists = roleUsers.find(u => u.id === username || u.email === email);

    if (exists) {
        return res.json({ success: false, message: 'User already exists.' });
    }

    roleUsers.push({ id: username, email, password });
    users[role] = roleUsers;

    return res.json({ success: true, message: 'Registration successful!', user: { id: username, email } });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
