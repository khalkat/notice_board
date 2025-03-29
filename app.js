require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const bcrypt = require('bcrypt');
const { db, dbOperations } = require('./database/db');
const ejs = require('ejs');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure session storage
const sessionStore = new SQLiteStore({
    db: 'sessions.db',
    dir: './database'
});

// Middleware setup
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 week
}));

// Template engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    next();
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (!req.session.user || req.session.user.role !== role) {
            return res.redirect('/');
        }
        next();
    };
};

// Routes
app.get('/', async (req, res) => {
    try {
        const notices = await dbOperations.getAllNotices();
        res.render('index', { 
            currentUser: req.session.user,
            notices: notices.slice(0, 5) // Show only 5 most recent on homepage
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

// Student routes
app.get('/student', requireRole('student'), async (req, res) => {
    try {
        const teachers = await dbOperations.getAllUsers();
        const notices = await dbOperations.getAllNotices();
        
        res.render('student', {
            user: req.session.user,
            teachers: teachers.filter(u => u.role === 'teacher'),
            notices: notices
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

app.post('/student/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await dbOperations.getUserByUsername(username);
        
        if (!user || user.role !== 'student') {
            return res.redirect('/?error=invalid-credentials');
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.redirect('/?error=invalid-credentials');
        }
        
        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role,
            full_name: user.full_name
        };
        
        res.redirect('/student');
    } catch (err) {
        console.error(err);
        res.redirect('/?error=server-error');
    }
});

// Teacher routes
app.get('/teacher', requireRole('teacher'), async (req, res) => {
    try {
        const notices = await dbOperations.getNoticesByTeacher(req.session.user.id);
        
        res.render('teacher', {
            user: req.session.user,
            activeTab: 'dashboard',
            notices: notices.slice(0, 3) // Show only 3 most recent on dashboard
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

app.get('/teacher/notices', requireRole('teacher'), async (req, res) => {
    try {
        const notices = await dbOperations.getNoticesByTeacher(req.session.user.id);
        
        res.render('teacher', {
            user: req.session.user,
            activeTab: 'notices',
            notices: notices
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

app.get('/teacher/post', requireRole('teacher'), (req, res) => {
    res.render('teacher', {
        user: req.session.user,
        activeTab: 'post',
        editing: false
    });
});

app.post('/teacher/post-notice', requireRole('teacher'), async (req, res) => {
    try {
        const { title, content, important } = req.body;
        
        await dbOperations.createNotice({
            title,
            content,
            posted_by: req.session.user.id,
            is_important: important === 'on'
        });
        
        res.redirect('/teacher/notices');
    } catch (err) {
        console.error(err);
        res.redirect('/teacher/post?error=server-error');
    }
});

app.get('/teacher/edit-notice/:id', requireRole('teacher'), async (req, res) => {
    try {
        const notice = await db.get(
            'SELECT * FROM notices WHERE id = ? AND posted_by = ?',
            [req.params.id, req.session.user.id]
        );
        
        if (!notice) {
            return res.redirect('/teacher/notices');
        }
        
        res.render('teacher', {
            user: req.session.user,
            activeTab: 'post',
            editing: true,
            notice: notice
        });
    } catch (err) {
        console.error(err);
        res.redirect('/teacher/notices?error=server-error');
    }
});

app.post('/teacher/update-notice', requireRole('teacher'), async (req, res) => {
    try {
        const { noticeId, title, content, important } = req.body;
        
        await db.run(
            'UPDATE notices SET title = ?, content = ?, is_important = ? WHERE id = ? AND posted_by = ?',
            [title, content, important === 'on', noticeId, req.session.user.id]
        );
        
        res.redirect('/teacher/notices');
    } catch (err) {
        console.error(err);
        res.redirect(`/teacher/edit-notice/${req.body.noticeId}?error=server-error`);
    }
});

app.post('/teacher/delete-notice', requireRole('teacher'), async (req, res) => {
    try {
        await db.run(
            'DELETE FROM notices WHERE id = ? AND posted_by = ?',
            [req.body.noticeId, req.session.user.id]
        );
        
        res.redirect('/teacher/notices');
    } catch (err) {
        console.error(err);
        res.redirect('/teacher/notices?error=server-error');
    }
});

// Admin routes
app.get('/admin', requireRole('admin'), async (req, res) => {
    try {
        const users = await dbOperations.getAllUsers();
        const notices = await dbOperations.getAllNotices();
        
        res.render('admin', {
            user: req.session.user,
            users: users,
            notices: notices
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

app.post('/admin/add-user', requireRole('admin'), async (req, res) => {
    try {
        await dbOperations.createUser(req.body);
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.redirect('/admin?error=user-exists');
    }
});

app.post('/admin/delete-user', requireRole('admin'), async (req, res) => {
    try {
        // Prevent admin from deleting themselves
        if (req.body.userId == req.session.user.id) {
            return res.redirect('/admin?error=cannot-delete-self');
        }
        
        await dbOperations.deleteUser(req.body.userId);
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.redirect('/admin?error=server-error');
    }
});

app.post('/admin/delete-notice', requireRole('admin'), async (req, res) => {
    try {
        await dbOperations.deleteNotice(req.body.noticeId);
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.redirect('/admin?error=server-error');
    }
});

// Common routes
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Session destruction error:', err);
        }
        res.redirect('/');
    });
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`LAN access: http://${getLocalIP()}:${PORT}`);
});

// Helper function to get local IP
function getLocalIP() {
    const interfaces = require('os').networkInterfaces();
    for (const devName in interfaces) {
        const iface = interfaces[devName];
        for (let i = 0; i < iface.length; i++) {
            const alias = iface[i];
            if (alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal) {
                return alias.address;
            }
        }
    }
    return 'localhost';
}