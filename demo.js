


// --- Continue with the rest of your code --


// --- MongoDB Connection ---
const MONGODB_URI = process.env.MONGODB_URI; 
// Retry connection with exponential backoff
const connectWithRetry = () => {
    console.log('MongoDB connection attempt...');
    mongoose.connect(MONGODB_URI).catch(err => {
        console.error('MongoDB connection error:', err);
        setTimeout(connectWithRetry, 5000);
    });
}; 

connectWithRetry();

mongoose.connection.on('connected', () => {
    console.log('✅ Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});


const studentListRequestSchema = new mongoose.Schema({
  teacherId: {
    type: String,
    required: true,
  },
  teacherTelegramId: {
    type: Number, // Telegram user ID is a number
    required: true,
    index: true,
  },
  className: {
    type: String,
    required: true,
    index: true,
  },
  subject: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'denied'],
    default: 'pending',
    index: true,
  },
  requestDate: {
    type: Date,
    default: Date.now,
  },
  approvalDate: Date,
  approvedBy: {
    type: Number, // Admin Telegram ID who approved/denied
  }
}, { timestamps: true });

const StudentListRequest = mongoose.model('StudentListRequest', studentListRequestSchema);

// Grade Schema
const gradeSchema = new mongoose.Schema({
  gradeId: { type: String, required: true },
  studentId: { type: String, required: true },
  studentName: { type: String, required: true },
  teacherId: { type: String, required: true },
  teacherName: { type: String, required: true },
  subject: { type: String, required: true },
  score: { type: Number, required: true, min: 0, max: 100 },
  purpose: { type: String, required: true, trim: true, maxlength: 100 }, // Allow any string, with validation
  comments: { type: String, default: '', maxlength: 500 },
  date: { type: Date, default: Date.now }
});

const Grade = mongoose.model('Grade', gradeSchema);


// OTP Schema for teacher registration
const otpSchema = new mongoose.Schema({
    telegramId: { type: String, required: true, unique: true, sparse: true },
    otp: { type: String, required: true },
    code: { type: String, sparse: true }, // Add this if needed
    expiresAt: { type: Date, required: true },
    attempts: { type: Number, default: 0 },
    verified: { type: Boolean, default: false }
}, { timestamps: true });

const OTP = mongoose.model('OTP', otpSchema);

// Teacher Login Schema
const teacherLoginSchema = new mongoose.Schema({
    teacherId: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    lastLogin: { type: Date },
    loginAttempts: { type: Number, default: 0 },
    lockedUntil: { type: Date }
}, { timestamps: true });

const TeacherLogin = mongoose.model('TeacherLogin', teacherLoginSchema);
// Update userSchema to include masterAdmin field
const userSchema = new mongoose.Schema({
    telegramId: { type: String, required: true, unique: true, sparse: true },
    username: { type: String },
    name: { type: String, default: 'User' },
    role: { type: String, enum: ['user', 'admin', 'parent', 'teacher'], default: 'user' },
    adminId: { type: String, unique: true, sparse: true},
    studentIds: [{ type: String }],
    subjects: [{ type: String }],
    pendingStudentIds: [{ type: String }],
    masterAdmin: { type: Boolean, default: false }, // Add this field
    lastActivity: { type: Date, default: Date.now }, // Add for monitoring
    activityLog: [{ // Add for detailed monitoring
        action: String,
        timestamp: { type: Date, default: Date.now },
        details: mongoose.Schema.Types.Mixed
    }]
}, { timestamps: true });

// Update the student schema
const studentSchema = new mongoose.Schema({
    studentId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    class: { type: String, required: true },
    parentId: { type: String, default: null },
    pendingParentId: { type: String, default: null },
}, { timestamps: true });

const teacherSchema = new mongoose.Schema({
    banned: { type: Boolean, default: false },

    teacherId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    telegramId: { 
        type: String, default:"", 
        unique: true, 
        sparse: true // This allows multiple null values
    },
    
    subjects: [{ type: String }],
    pendingSubjects: [{ type: String }]
}, { timestamps: true });


const uploadedFileSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    originalName: { type: String, required: true },
    storedName: { type: String, required: true },
    uploadDate: { type: Date, default: Date.now },
    processed: { type: Boolean, default: false },
    classAssigned: { type: String, required: true }
});
// Teacher-Student Relationship Schema
const teacherStudentSchema = new mongoose.Schema({
    teacherId: { type: String, required: true },
    teacherName: { type: String, required: true },
    studentId: { type: String, required: true },
    studentName: { type: String, required: true },
    subject: { type: String, required: true },
    className: { type: String, required: true },
    addedDate: { type: Date, default: Date.now }
}, { timestamps: true });

// Compound index to prevent duplicates
teacherStudentSchema.index({ teacherId: 1, studentId: 1, subject: 1 }, { unique: true });

const TeacherStudent = mongoose.model('TeacherStudent', teacherStudentSchema);


// Attendance Schema
const attendanceSchema = new mongoose.Schema({
    attendanceId: { type: String, required: true, unique: true },
    teacherId: { type: String, required: true },
    teacherName: { type: String, required: true },
    subject: { type: String, required: true },
    className: { type: String, required: true },
    date: { type: Date, required: true },
    students: [{
        studentId: { type: String, required: true },
        studentName: { type: String, required: true },
        status: { type: String, enum: ['present', 'absent'], required: true },
        parentNotified: { type: Boolean, default: false }
    }],
    totalStudents: { type: Number, required: true },
    presentCount: { type: Number, required: true },
    absentCount: { type: Number, required: true }
}, { timestamps: true });

const Attendance = mongoose.model('Attendance', attendanceSchema);


// Teacher Settings Schema
const teacherSettingsSchema = new mongoose.Schema({
    teacherId: { type: String, required: true, unique: true },
    attendanceReminder: { type: Boolean, default: true },
    reminderTime: { type: String, default: "08:00" } // 24-hour format
}, { timestamps: true });

const TeacherSettings = mongoose.model('TeacherSettings', teacherSettingsSchema);

// --- Models ---
const User = mongoose.model('User', userSchema);
const Student = mongoose.model('Student', studentSchema);
const Teacher = mongoose.model('Teacher', teacherSchema);
const UploadedFile = mongoose.model('UploadedFile', uploadedFileSchema);
//
//
//
//
//
////
//
//
//
//

//helper Functions
//
//
//
//
//
//
// Add to helper functions in school-bot.js
const logDbChange = async (telegramId, model, operation, targetId, details = {}) => {
    try {
        const user = await User.findOne({ telegramId });
        const adminInfo = user ? { name: user.name, id: telegramId } : { name: 'DB Manager', id: telegramId };
        
        await notifyMasterAdmin({ from: adminInfo }, 'db_manager_action', {
            model,
            operation,
            targetId,
            details
        });
    } catch (error) {
        console.error('Error logging DB change:', error);
    }
};

// Daily attendance reminder system
const setupAttendanceReminders = () => {
    // Check every minute if it's time to send reminders
    setInterval(async () => {
        try {
            const now = new Date();
            const currentTime = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
            
            // Get all teachers with reminders enabled
            const settings = await TeacherSettings.find({ 
                attendanceReminder: true,
                reminderTime: currentTime
            });
            
            for (const setting of settings) {
                const teacher = await Teacher.findOne({ teacherId: setting.teacherId });
                if (teacher && teacher.telegramId) {
                    try {
                        await bot.telegram.sendMessage(
                            teacher.telegramId,
                            `🔔 *Daily Attendance Reminder*\n\n` +
                            `It's time to take attendance for your classes today!\n\n` +
                            `Use the "📝 Record Attendance" option in your teacher menu to record attendance for your subjects.`,
                            { parse_mode: "HTML" }
                        );
                    } catch (error) {
                        console.error(`Failed to send reminder to teacher ${teacher.teacherId}:`, error);
                    }
                }
            }
        } catch (error) {
            console.error('Error in attendance reminder system:', error);
        }
    }, 60000); // Check every minute
};

// Start the reminder system when bot starts
setupAttendanceReminders();

// Generate unique attendance ID
const generateUniqueAttendanceId = async () => {
    let attendanceId;
    let exists;
    do {
        const randomDigits = crypto.randomInt(1000, 9999).toString();
        attendanceId = `AT${randomDigits}`;
        exists = await Attendance.findOne({ attendanceId });
    } while (exists);
    return attendanceId;
};

// Helper function to check if user is registered as teacher
const isUserRegisteredTeacher = async (telegramId) => {
    try {
        const teacher = await Teacher.findOne({ telegramId });
        return teacher !== null;
    } catch (error) {
        console.error('Error checking teacher registration:', error);
        return false;
    }
};
// Clean up expired OTPs every hour
setInterval(async () => {
    try {
        const result = await OTP.deleteMany({ 
            expiresAt: { $lt: new Date() } 
        });
        
        if (result.deletedCount > 0) {
            console.log(`Cleaned up ${result.deletedCount} expired OTPs`);
        }
    } catch (error) {
        console.error('Error cleaning up expired OTPs:', error);
    }
}, 60 * 60 * 1000); // Run every hour


// Add this helper function to get rich teacher information
const getRichTeacherInfo = async (telegramId) => {
    try {
        const teacher = await Teacher.findOne({ telegramId });
        if (!teacher) return null;

        // Get student count and subject statistics
        const subjectStats = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: {
                _id: '$subject',
                studentCount: { $sum: 1 }
            }},
            { $sort: { studentCount: -1 } }
        ]);

        const studentCount = subjectStats.reduce((sum, stat) => sum + stat.studentCount, 0);

        return {
            name: teacher.name,
            teacherId: teacher.teacherId,
            telegramId: teacher.telegramId,
            username: teacher.username,
            subjects: teacher.subjects || [],
            subjectStats: subjectStats,
            studentCount: studentCount,
            registrationDate: teacher.createdAt
        };
    } catch (error) {
        console.error('Error getting rich teacher info:', error);
        return null;
    }
};
// Add this helper function to format list information
const getFormattedListInfo = async (teacherId, className) => {
    const listInfo = await TeacherStudent.aggregate([
        { $match: { teacherId: teacherId, className: className } },
        { $group: {
            _id: null,
            totalStudents: { $sum: 1 },
            subjects: { $addToSet: '$subject' },
            firstAdded: { $min: '$addedDate' },
            lastAdded: { $max: '$addedDate' },
            studentNames: { $push: '$studentName' }
        }}
    ]);

    if (!Array.isArray(listInfo) || listInfo.length === 0 || !listInfo[0]) return null;

    const group = listInfo[0];

    return {
        totalStudents: group.totalStudents || 0,
        subjects: group.subjects || [],
        subjectCount: (group.subjects || []).length,
        firstAdded: group.firstAdded || null,
        lastAdded: group.lastAdded || null,
        sampleStudents: (group.studentNames || []).slice(0, 5) // First 5 students
    };
};
const getUniqueClasses = async () => {
    try {
        const classes = await Student.distinct('class');
        return classes.filter(className => className && className.trim() !== '');
    } catch (err) {
        console.error('Error getting unique classes:', err);
        return [];
    }
};
const processTeacherStudentUpload = async (ctx, studentIds, subject) => {
    const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
    if (!teacher) {
        return ctx.reply('❌ Teacher profile not found. Please contact an admin.');
    }

    const { teacherId, name: teacherName } = teacher;
    let successfulCreations = 0;
    let failedCreations = 0;
    const failedStudents = [];

    for (const studentId of studentIds) {
        try {
            const student = await Student.findOne({ studentId });
            if (student) {
                // Check if the relationship already exists to prevent duplicates
                const existingRelation = await TeacherStudent.findOne({
                    teacherId,
                    studentId,
                    subject
                });

                if (!existingRelation) {
                    const newRelation = new TeacherStudent({
                        teacherId,
                        teacherName,
                        studentId,
                        studentName: student.name,
                        subject,
                        className: student.class
                    });
                    await newRelation.save();
                    successfulCreations++;
                } else {
                    // It's not a failure, just a duplicate that we don't need to add again
                    successfulCreations++;
                }
            } else {
                failedCreations++;
                failedStudents.push(studentId);
            }
        } catch (error) {
            if (error.code === 11000) { // MongoDB duplicate key error
                // This case is already handled by the findOne check, but good to have
                // a fallback just in case.
                successfulCreations++;
            } else {
                console.error(`Error creating relationship for student ${studentId}:`, error);
                failedCreations++;
                failedStudents.push(studentId);
            }
        }
    }

    let replyMessage = `✅ Finished processing student list.\n\n`;
    replyMessage += `• Successful links created: ${successfulCreations}\n`;
    replyMessage += `• Failed to link (student ID not found): ${failedCreations}\n`;

    if (failedStudents.length > 0) {
        replyMessage += `\n❌ The following IDs could not be found:\n`;
        replyMessage += failedStudents.join(', ');
    }

    ctx.reply(replyMessage);
    ctx.scene.leave();
};




const getUserByUsername = async (username) => {
    try {
        // This assumes usernames are stored in the name field
        // Adjust based on your actual schema
        return await User.findOne({ 
            name: new RegExp(`^${username}$`, 'i')
        });
    } catch (err) {
        console.error('Error getting user by username:', err);
        return null;
    }
};

// --- Models ---

// --- Bot Initialization ---
const bot = new Telegraf(process.env.BOT_TOKEN);
console.log('Initializing...');

// --- Input Validation Functions ---
const isValidStudentId = (id) => {
    return /^ST-?\d{4}$/i.test(id);
};

const isValidTeacherId = (id) => /^TE\d{4}$/.test(id);
const isValidAdminId = (id) => /^AD\d{2}$/.test(id);

const isValidTelegramId = (id) => /^\d+$/.test(id);
const isValidName = (name) => name && name.trim().length > 0 && name.trim().length <= 100;
const isValidClassName = (className) => className && className.trim().length > 0 && className.trim().length <= 50;
const isValidSubject = (subject) => subject && subject.trim().length > 0 && subject.trim().length <= 50;


const isValidAnnouncementOrMessage = (text) => text && text.trim().length > 0;

// --- Helper Functions ---

const getUserById = async (telegramId) => {
    try {
        return await User.findOne({ telegramId });
    } catch (err) {
        console.error('Error getting user by ID:', err);
        return null;
    }
};

const getStudentById = async (studentId) => {
    try {
        return await Student.findOne({ studentId });
    } catch (err) {
        console.error('Error getting student by ID:', err);
        return null;
    }
};

const getStudentsByParentId = async (parentId) => {
    try {
        return await Student.find({ parentId });
    } catch (err) {
        console.error('Error getting students by parent ID:', err);
        return [];
    }
};

const getTeacherById = async (teacherId) => {
    try {
        return await Teacher.findOne({ teacherId });
    } catch (err) {
        console.error('Error getting teacher by ID:', err);
        return null;
    }
};

const getAdmins = async () => {
    try {
        return await User.find({ role: 'admin' });
    } catch (err) {
        console.error('Error getting admins:', err);
        return [];
    }
};

// Unique ID Generators
// --- Helper Functions ---
//
//
//
// --- Master Admin Middleware and Monitoring System ---

// Helper function to generate detailed deletion log
const generateClassDeletionLog = (className, deletedStudents, unlinkedParents, deletedTeacherRelations, studentDetails, parentDetails, teacherRelations, adminInfo) => {
    let logContent = `CLASS DELETION REPORT\n`;
    logContent += '='.repeat(80) + '\n\n';
    logContent += `Class: ${className}\n`;
    logContent += `Deleted by: ${adminInfo.first_name || 'Admin'} ${adminInfo.last_name || ''} (ID: ${adminInfo.id})\n`;
    logContent += `Timestamp: ${new Date().toLocaleString()}\n`;
    logContent += '='.repeat(80) + '\n\n';
    
    logContent += 'SUMMARY:\n';
    logContent += '='.repeat(80) + '\n';
    logContent += `Total Students Deleted: ${deletedStudents}\n`;
    logContent += `Parents Unlinked: ${unlinkedParents}\n`;
    logContent += `Teacher Relationships Removed: ${deletedTeacherRelations}\n\n`;
    
    logContent += 'STUDENTS DELETED:\n';
    logContent += '='.repeat(80) + '\n';
    studentDetails.forEach((student, index) => {
        logContent += `${index + 1}. ${student.studentName} (ID: ${student.studentId})\n`;
    });
    if (studentDetails.length === 0) {
        logContent += 'No students found in this class.\n';
    }
    logContent += '\n';
    
    logContent += 'PARENTS UNLINKED:\n';
    logContent += '='.repeat(80) + '\n';
    parentDetails.forEach((parent, index) => {
        logContent += `${index + 1}. ${parent.parentName} (ID: ${parent.parentId}) - Student: ${parent.studentId}\n`;
    });
    if (parentDetails.length === 0) {
        logContent += 'No parents were linked to students in this class.\n';
    }
    logContent += '\n';
    
    logContent += 'TEACHER RELATIONSHIPS REMOVED:\n';
    logContent += '='.repeat(80) + '\n';
    teacherRelations.slice(0, 20).forEach((relation, index) => {
        logContent += `${index + 1}. ${relation.teacherName} (${relation.teacherId}) -> ${relation.studentName} (${relation.studentId}) - ${relation.subject}\n`;
    });
    if (teacherRelations.length > 20) {
        logContent += `... and ${teacherRelations.length - 20} more relationships\n`;
    }
    if (teacherRelations.length === 0) {
        logContent += 'No teacher relationships found for this class.\n';
    }
    
    return logContent;
};
// Enhanced notifyMasterAdmin function to support message updates and real-time notifications
const notifyMasterAdmin = async (ctx, action, details = {}, messageId = null) => {
    try {
        const masterAdminId = process.env.MASTER_ADMIN_ID;
        if (!masterAdminId) return null;

        const admin = ctx.from ? await getUserById(ctx.from.id) : null;
        const adminInfo = admin ? `${admin.name} (ID: ${admin.telegramId})` : 'Unknown';

        let message = `🔍 <b>Admin Action Alert</b>\n\n`;
        message += `👤 <b>Admin:</b> ${adminInfo}\n`;
        message += `⏰ <b>Time:</b> ${new Date().toLocaleString()}\n`;
        message += `🔧 <b>Action:</b> ${action}\n`;

        if (details) {
            // Class deletion specific details
            if (details.className) {
                message += `🏫 <b>Class:</b> ${details.className}\n`;
            }
            if (details.progress !== undefined && details.total !== undefined) {
                message += `📊 <b>Progress:</b> ${details.progress}/${details.total} (${details.percentage}%)\n`;
            }
            if (details.eta) {
                message += `⏰ <b>ETA:</b> ${details.eta}\n`;
            }
            if (details.speed) {
                message += `🏎️ <b>Speed:</b> ${details.speed} students/sec\n`;
            }
            if (details.statistics) {
                message += `📈 <b>Results:</b> ${details.statistics.deletedStudents} students, ` +
                          `${details.statistics.unlinkedParents} parents, ` +
                          `${details.statistics.deletedTeacherRelations} teacher relations\n`;
            }
            if (details.totalTime) {
                message += `⏱️ <b>Total Time:</b> ${details.totalTime}\n`;
            }
            
            // Original details handling (keep existing functionality)
            if (details.messageText) {
                message += `💬 <b>Message:</b> ${details.messageText.substring(0, 100)}...\n`;
            }
            if (details.command) {
                message += `🔧 <b>Command:</b> ${details.command}\n`;
            }
            if (details.removedAdmin) {
                message += `🗑️ <b>Removed Admin:</b> ${details.removedAdmin}\n`;
            }
            if (details.promotedUser) {
                message += `👑 <b>Promoted User:</b> ${details.promotedUser}\n`;
            }
            if (details.chatType) {
                message += `💬 <b>Chat Type:</b> ${details.chatType}\n`;
            }
            if (details.uploadedFile) {
                message += `📤 <b>Uploaded:</b> ${details.uploadedFile.name} (Class: ${details.uploadedFile.class})\n`;
            }
            if (details.removedFileId) {
                message += `🗑️ <b>Removed File ID:</b> ${details.removedFileId}\n`;
            }
            if (details.model) {
                message += `⚙️ <b>DB Change:</b> ${details.model}.${details.operation} (Target: ${details.targetId})\n`;
            }
            if (details.error) {
                message += `❌ <b>Error:</b> ${details.error}\n`;
            }
        }

        // If messageId is provided, try to update existing message
        if (messageId) {
            try {
                return await bot.telegram.editMessageText(
                    masterAdminId,
                    messageId,
                    null,
                    message,
                    { parse_mode: 'HTML' }
                );
            } catch (editError) {
                // If message can't be edited (too old or not found), send a new one
                console.log('Cannot edit message, sending new one:', editError.message);
                // Continue to send new message
            }
        }

        // Send new message
        return await bot.telegram.sendMessage(masterAdminId, message, { 
            parse_mode: 'HTML' 
        });

    } catch (error) {
        console.error('Error notifying master admin:', error);
        return null;
    }
};
// Master admin authorization middleware
const requireMasterAdmin = async (ctx, next) => {
    try {
        const masterAdminId = process.env.MASTER_ADMIN_ID;
        
        if (!masterAdminId) {
            ctx.reply('❌ Master admin system not configured.');
            return;
        }

        // Check if user is the master admin
        if (ctx.from.id.toString() !== masterAdminId) {
            ctx.reply('❌ Access denied. Master admin privileges required.');
            return;
        }

        // Ensure master admin record exists in database
        let masterAdminUser = await User.findOne({ telegramId: masterAdminId });
        if (!masterAdminUser) {
            // Create master admin user if doesn't exist
            masterAdminUser = new User({
                telegramId: masterAdminId,
                name: ctx.from.first_name || 'Master Admin',
                role: 'admin',
                masterAdmin: true
            });
            await masterAdminUser.save();
        } else if (!masterAdminUser.masterAdmin) {
            // Upgrade to master admin if not already
            masterAdminUser.masterAdmin = true;
            masterAdminUser.role = 'admin';
            await masterAdminUser.save();
        }

        ctx.state.masterAdmin = masterAdminUser;
        await trackAdminActivity(ctx, 'master_admin_access');
        return next();
        
    } catch (error) {
        console.error('Master admin auth error:', error);
        ctx.reply('❌ Authorization error. Please try again.');
    }
};

// Monitor all admin commands
bot.use(async (ctx, next) => {
    if (ctx.message && ctx.message.text && ctx.message.text.startsWith('/')) {
        const command = ctx.message.text.split(' ')[0];
        if (command.includes('admin') || command.includes('manage')) {
            await trackAdminActivity(ctx, 'admin_command', { command });
        }
    }
    return next();
});
const getLoginMenu = async (telegramId) => {
    const user = await getUserById(telegramId);
    if (user) {
        switch (user.role) {
            case 'teacher':
                return postLogoutMenu;
            case 'admin':
                return adminMenu;
            case 'parent':
                return parentMenu;
            default:
                return loginMenu;
        }
    }
    return loginMenu;
};
// Authorization middleware for teacher routes
// Authorization middleware for teacher routes - FIXED VERSION
const requireTeacherAuth = async (ctx, next) => {
    try {
        // First check if user is already a registered teacher
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (teacher.banned) {
    ctx.reply('❌ Your access has been banned. Please contact an administrator.');
    return;
  }

        if (teacher) {
            // User is a registered teacher, check user role
            const user = await getUserById(ctx.from.id);
            if (user && user.role === 'teacher') {
                ctx.state.teacher = teacher;
                return next();
            } else {
                // Teacher exists but user role is wrong - fix it
                if (user) {
                    user.role = 'teacher';
                    await user.save();
                    ctx.state.teacher = teacher;
                    return next();
                }
            }
        }
        
        // If not a teacher, show appropriate message
        ctx.reply('❌ You are not registered as a teacher yet. Please use the "👨‍🏫 Teacher Registration" option first.', loginMenu);
        
    } catch (error) {
        console.error('Authorization error:', error);
        ctx.reply('❌ An error occurred during authorization. Please try again.');
    }
};

// Generate 6-digit OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Generate 6-digit password
const generatePassword = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Check if OTP is expired
const isOTPExpired = (expiresAt) => {
    return new Date() > expiresAt;
};

// Hash password (simple implementation)
const hashPassword = (password) => {
    return crypto.createHash('sha256').update(password).digest('hex');
};

// Verify password
const verifyPassword = (password, hashedPassword) => {
    return hashPassword(password) === hashedPassword;
};

// Check if account is locked
const isAccountLocked = (lockedUntil) => {
    return lockedUntil && new Date() < lockedUntil;
};

const viewStudentGrades = async (studentId, subject = null) => {
    try {
        const student = await getStudentById(studentId);
        if (!student) return null;
        
        const grades = await getStudentGrades(studentId, subject);
        
        return {
            student: student.name,
            studentId: student.studentId,
            class: student.class,
            grades: grades.map(grade => ({
                subject: grade.subject,
                score: grade.score,
                purpose: grade.purpose,
                date: grade.date,
                comments: grade.comments,
                teacher: grade.teacherName
            }))
        };
    } catch (error) {
        console.error('Error viewing student grades:', error);
        return null;
    }
};
// Get students by teacher and subject
const getStudentsByTeacherAndSubject = async (teacherId, subject) => {
    try {
        return await TeacherStudent.find({ 
            teacherId, 
            subject 
        }).sort({ studentName: 1 }); // Sort alphabetically
    } catch (err) {
        console.error('Error getting students by teacher and subject:', err);
        return [];
    }
};

// Get student grades
const getStudentGrades = async (studentId, subject = null) => {
    try {
        const query = { studentId };
        if (subject) query.subject = subject;
        return await Grade.find(query).sort({ date: -1 });
    } catch (err) {
        console.error('Error getting student grades:', err);
        return [];
    }
};

// Generate unique grade ID
const generateUniqueGradeId = async () => {
    let gradeId;
    let exists;
    do {
        const randomDigits = crypto.randomInt(1000, 9999).toString();
        gradeId = `GR${randomDigits}`;
        exists = await Grade.findOne({ gradeId });
    } while (exists);
    return gradeId;
};

// Update the unique ID generators

// Student ID generator: ST + 4 digits (e.g., ST3412)
const generateUniqueStudentId = async () => {
    let studentId;
    let exists;
    do {
        const randomDigits = crypto.randomInt(1000, 9999).toString();
        studentId = `ST${randomDigits}`;
        exists = await Student.findOne({ studentId });
    } while (exists);
    return studentId;
};

// Teacher ID generator: TE + 4 digits (e.g., TE4001)
const generateUniqueTeacherId = async () => {
    let teacherId;
    let exists;
    do {
        const randomDigits = crypto.randomInt(1000, 9999).toString();
        teacherId = `TE${randomDigits}`;
        exists = await Teacher.findOne({ teacherId });
    } while (exists);
    return teacherId;
};

// Admin ID generator: AD + 2 digits (e.g., AD12)
const generateUniqueAdminId = async () => {
    let adminId;
    let exists;
    do {
        const randomDigits = crypto.randomInt(10, 99).toString();
        adminId = `AD${randomDigits}`;
        exists = await User.findOne({ adminId }); // Assuming you might want to store admin IDs
    } while (exists);
    return adminId;
};



// --- State Management ---
const { leave } = Scenes.Stage;
const stage = new Scenes.Stage();

bot.use(session());
bot.use(stage.middleware());
// --- Scene Definitions --------------------------------------
//
//
//
//
//
//
//
//
//
//
//

// Teacher My Subjects Scene
const teacherMySubjectsScene = new Scenes.BaseScene('teacher_my_subjects_scene');

teacherMySubjectsScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        const currentSubjects = teacher.subjects || [];
        const pendingSubjects = teacher.pendingSubjects || [];

        let message = '📚 *My Subjects*\n\n';
        
        if (currentSubjects.length > 0) {
            message += '✅ *Approved Subjects:*\n';
            currentSubjects.forEach((subject, index) => {
                message += `${index + 1}. ${subject}\n`;
            });
            message += '\n';
        }

        if (pendingSubjects.length > 0) {
            message += '⏳ *Pending Approval:*\n';
            pendingSubjects.forEach((subject, index) => {
                message += `${index + 1}. ${subject}\n`;
            });
            message += '\n';
        }

        if (currentSubjects.length === 0 && pendingSubjects.length === 0) {
            message += '📝 You have no subjects yet. Add your first subject!\n\n';
        }

        // Create action buttons
        const buttons = [
            [Markup.button.callback('➕ Add New Subject', 'add_new_subject')]
        ];

        if (currentSubjects.length > 0) {
            buttons.push(
                [Markup.button.callback('✏️ Edit Subject Name', 'edit_subject_name')],
                [Markup.button.callback('🗑️ Delete Subject', 'delete_subject')]
            );
        }

        buttons.push([Markup.button.callback('❌ Close', 'close_subjects')]);

        ctx.replyWithHTML(message, Markup.inlineKeyboard(buttons));

    } catch (error) {
        console.error('Error in teacher my subjects scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Add New Subject Scene
const addNewSubjectScene = new Scenes.BaseScene('add_new_subject_scene');

addNewSubjectScene.enter((ctx) => {
    ctx.reply(
        '📝 *Add New Subject*\n\n' +
        'Please enter the name of the subject you want to add:\n\n' +
        '📋 *Examples:* Mathematics, English Language, Physics, Chemistry\n' +
        '💡 *Tip:* Use clear and descriptive subject names',
        Markup.keyboard([['❌ Cancel']]).resize()
    );
});

addNewSubjectScene.on('text', async (ctx) => {
    const subjectName = ctx.message.text.trim();
    
    if (subjectName === '❌ Cancel') {
        ctx.reply('❌ Subject addition cancelled.', teacherMenu);
        return ctx.scene.leave();
    }

    if (!isValidSubject(subjectName)) {
        ctx.reply('❌ Invalid subject name. Please enter a valid subject name (1-50 characters).');
        return;
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Check if subject already exists (approved or pending)
        const allSubjects = [...teacher.subjects, ...teacher.pendingSubjects];
        if (allSubjects.includes(subjectName)) {
            ctx.reply('❌ This subject is already in your list (either approved or pending).');
            return;
        }

        // Add to pending subjects
        teacher.pendingSubjects = teacher.pendingSubjects || [];
        teacher.pendingSubjects.push(subjectName);
        await teacher.save();

        // Notify admins
        const admins = await getAdmins();
        for (const admin of admins) {
            try {
                await ctx.telegram.sendMessage(
                    admin.telegramId,
                    `📋 *New Subject Request*\n\n` +
                    `👤 Teacher: ${teacher.name} (${teacher.teacherId})\n` +
                    `📚 Subject: ${subjectName}\n` +
                    `📅 Requested: ${new Date().toLocaleString()}\n\n` +
                    `Please approve or deny this subject request:`,
                    Markup.inlineKeyboard([
                        [
                            Markup.button.callback('✅ Approve', `approve_subject_${teacher.teacherId}_${subjectName.replace(/ /g, '_')}`),
                            Markup.button.callback('❌ Deny', `deny_subject_${teacher.teacherId}_${subjectName.replace(/ /g, '_')}`)
                        ]
                    ])
                );
            } catch (error) {
                console.error(`Failed to notify admin ${admin.telegramId}:`, error);
            }
        }

        ctx.replyWithHTML(
            `✅ *Subject Request Submitted!*\n\n` +
            `📚 Subject: ${subjectName}\n` +
            `⏳ Status: Pending admin approval\n\n` +
            `You'll be notified once an admin reviews your request.`,
            teacherMenu
        );

        // Track activity
        await trackAdminActivity(ctx, 'subject_request_submitted', {
            teacherId: teacher.teacherId,
            teacherName: teacher.name,
            subject: subjectName
        });

    } catch (error) {
        console.error('Error adding new subject:', error);
        ctx.reply('❌ An error occurred while adding the subject.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Edit Subject Name Scene
const editSubjectNameScene = new Scenes.BaseScene('edit_subject_name_scene');

editSubjectNameScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no approved subjects to edit.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `edit_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_edit_subject')]);

        ctx.reply(
            '✏️ *Edit Subject Name*\n\n' +
            'Select the subject you want to rename:',
            Markup.inlineKeyboard(subjectButtons)
        );

    } catch (error) {
        console.error('Error in edit subject scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

editSubjectNameScene.action(/^edit_subject_(.+)$/, async (ctx) => {
    const oldSubjectName = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    ctx.session.editingSubject = oldSubjectName;
    
    ctx.reply(
        `✏️ Editing: ${oldSubjectName}\n\n` +
        'Please enter the new name for this subject:',
        Markup.keyboard([['❌ Cancel']]).resize()
    );
});

editSubjectNameScene.on('text', async (ctx) => {
    const newSubjectName = ctx.message.text.trim();
    const oldSubjectName = ctx.session.editingSubject;
    
    if (newSubjectName === '❌ Cancel') {
        ctx.reply('❌ Subject editing cancelled.', teacherMenu);
        delete ctx.session.editingSubject;
        return ctx.scene.leave();
    }

    if (!isValidSubject(newSubjectName)) {
        ctx.reply('❌ Invalid subject name. Please enter a valid subject name (1-50 characters).');
        return;
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Check if new name already exists
        if (teacher.subjects.includes(newSubjectName) || teacher.pendingSubjects.includes(newSubjectName)) {
            ctx.reply('❌ This subject name is already in use.');
            return;
        }

        // Update subject name in teacher's subjects
        const subjectIndex = teacher.subjects.indexOf(oldSubjectName);
        if (subjectIndex !== -1) {
            teacher.subjects[subjectIndex] = newSubjectName;
            await teacher.save();

            // Update all teacher-student relationships with the new subject name
            await TeacherStudent.updateMany(
                { teacherId: teacher.teacherId, subject: oldSubjectName },
                { $set: { subject: newSubjectName } }
            );

            // Update all grades with the new subject name
            await Grade.updateMany(
                { teacherId: teacher.teacherId, subject: oldSubjectName },
                { $set: { subject: newSubjectName } }
            );

            // Update all attendance records with the new subject name
            await Attendance.updateMany(
                { teacherId: teacher.teacherId, subject: oldSubjectName },
                { $set: { subject: newSubjectName } }
            );

            ctx.replyWithHTML(
                `✅ *Subject Renamed Successfully!*\n\n` +
                `📛 Old Name: ${oldSubjectName}\n` +
                `📛 New Name: ${newSubjectName}\n\n` +
                `All student relationships, grades, and attendance records have been updated.`,
                teacherMenu
            );

            // Track activity
            await trackAdminActivity(ctx, 'subject_renamed', {
                teacherId: teacher.teacherId,
                teacherName: teacher.name,
                oldSubject: oldSubjectName,
                newSubject: newSubjectName
            });
        }

    } catch (error) {
        console.error('Error editing subject:', error);
        ctx.reply('❌ An error occurred while editing the subject.', teacherMenu);
    }
    
    delete ctx.session.editingSubject;
    ctx.scene.leave();
});

editSubjectNameScene.action('cancel_edit_subject', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Subject editing cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Delete Subject Scene
const deleteSubjectScene = new Scenes.BaseScene('delete_subject_scene');

deleteSubjectScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no approved subjects to delete.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `delete_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_delete_subject')]);

        ctx.reply(
            '🗑️ *Delete Subject*\n\n' +
            'Select the subject you want to delete:\n\n' +
            '⚠️ *Warning:* This will also remove all students, grades, and attendance records for this subject!',
            Markup.inlineKeyboard(subjectButtons)
        );

    } catch (error) {
        console.error('Error in delete subject scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

deleteSubjectScene.action(/^delete_subject_(.+)$/, async (ctx) => {
    const subjectName = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get statistics for confirmation
        const studentCount = await TeacherStudent.countDocuments({
            teacherId: teacher.teacherId,
            subject: subjectName
        });
        
        const gradeCount = await Grade.countDocuments({
            teacherId: teacher.teacherId,
            subject: subjectName
        });
        
        const attendanceCount = await Attendance.countDocuments({
            teacherId: teacher.teacherId,
            subject: subjectName
        });

        ctx.session.subjectToDelete = subjectName;
        ctx.session.deleteStats = { studentCount, gradeCount, attendanceCount };

        ctx.replyWithHTML(
            `⚠️ *CONFIRM SUBJECT DELETION*\n\n` +
            `📚 Subject: ${subjectName}\n\n` +
            `📊 This will permanently delete:\n` +
            `• ${studentCount} student relationships\n` +
            `• ${gradeCount} grade records\n` +
            `• ${attendanceCount} attendance records\n\n` +
            `❌ *This action cannot be undone!*\n\n` +
            `Are you sure you want to proceed?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Delete Everything', 'confirm_subject_deletion')],
                [Markup.button.callback('❌ No, Cancel', 'cancel_delete_subject')]
            ])
        );

    } catch (error) {
        console.error('Error preparing subject deletion:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

deleteSubjectScene.action('confirm_subject_deletion', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const subjectName = ctx.session.subjectToDelete;
        const { studentCount, gradeCount, attendanceCount } = ctx.session.deleteStats;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        // Remove subject from teacher's list
        teacher.subjects = teacher.subjects.filter(subj => subj !== subjectName);
        await teacher.save();

        // Delete all related data
        await TeacherStudent.deleteMany({
            teacherId: teacher.teacherId,
            subject: subjectName
        });

        await Grade.deleteMany({
            teacherId: teacher.teacherId,
            subject: subjectName
        });

        await Attendance.deleteMany({
            teacherId: teacher.teacherId,
            subject: subjectName
        });

        ctx.replyWithHTML(
            `✅ *Subject Deleted Successfully!*\n\n` +
            `📚 Subject: ${subjectName}\n\n` +
            `🗑️ Removed:\n` +
            `• ${studentCount} student relationships\n` +
            `• ${gradeCount} grade records\n` +
            `• ${attendanceCount} attendance records\n\n` +
            `All data for this subject has been permanently deleted.`,
            teacherMenu
        );

        // Track activity
        await trackAdminActivity(ctx, 'subject_deleted', {
            teacherId: teacher.teacherId,
            teacherName: teacher.name,
            subject: subjectName,
            statistics: { studentCount, gradeCount, attendanceCount }
        });

    } catch (error) {
        console.error('Error deleting subject:', error);
        ctx.reply('❌ An error occurred while deleting the subject.', teacherMenu);
    }
    
    delete ctx.session.subjectToDelete;
    delete ctx.session.deleteStats;
    ctx.scene.leave();
});

deleteSubjectScene.action('cancel_delete_subject', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Subject deletion cancelled.', teacherMenu);
    delete ctx.session.subjectToDelete;
    delete ctx.session.deleteStats;
    ctx.scene.leave();
});

// Handle subject approval/denial from admins
bot.action(/^approve_subject_(.+)_(.+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    
    const teacherId = ctx.match[1];
    const subjectName = ctx.match[2].replace(/_/g, ' ');
    
    try {
        const teacher = await Teacher.findOne({ teacherId });
        if (!teacher) {
            ctx.reply('❌ Teacher not found.');
            return;
        }

        // Move from pending to approved
        teacher.pendingSubjects = teacher.pendingSubjects.filter(subj => subj !== subjectName);
        teacher.subjects = teacher.subjects || [];
        teacher.subjects.push(subjectName);
        await teacher.save();

        // Notify teacher
        await ctx.telegram.sendMessage(
            teacher.telegramId,
            `✅ *Subject Approved!*\n\n` +
            `📚 Subject: ${subjectName}\n` +
            `👤 Approved by: ${ctx.from.first_name}\n` +
            `⏰ ${new Date().toLocaleString()}\n\n` +
            `You can now use this subject for your classes.`,
            { parse_mode: "HTML" }
        );

        // Update the admin message
        await ctx.editMessageText(
            `✅ *Subject Approved*\n\n` +
            `👤 Teacher: ${teacher.name} (${teacherId})\n` +
            `📚 Subject: ${subjectName}\n` +
            `✅ Approved by: ${ctx.from.first_name}\n` +
            `⏰ ${new Date().toLocaleString()}`,
            { parse_mode: "HTML" }
        );

        // Track activity
        await trackAdminActivity(ctx, 'subject_approved', {
            teacherId: teacher.teacherId,
            teacherName: teacher.name,
            subject: subjectName
        });

    } catch (error) {
        console.error('Error approving subject:', error);
        ctx.reply('❌ An error occurred while approving the subject.');
    }
});

bot.action(/^deny_subject_(.+)_(.+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    
    const teacherId = ctx.match[1];
    const subjectName = ctx.match[2].replace(/_/g, ' ');
    
    try {
        const teacher = await Teacher.findOne({ teacherId });
        if (!teacher) {
            ctx.reply('❌ Teacher not found.');
            return;
        }

        // Remove from pending
        teacher.pendingSubjects = teacher.pendingSubjects.filter(subj => subj !== subjectName);
        await teacher.save();

        // Notify teacher
        await ctx.telegram.sendMessage(
            teacher.telegramId,
            `❌ *Subject Request Denied*\n\n` +
            `📚 Subject: ${subjectName}\n` +
            `👤 Denied by: ${ctx.from.first_name}\n` +
            `⏰ ${new Date().toLocaleString()}\n\n` +
            `Please contact an admin if you have questions.`,
            { parse_mode: "HTML" }
        );

        // Update the admin message
        await ctx.editMessageText(
            `❌ *Subject Denied*\n\n` +
            `👤 Teacher: ${teacher.name} (${teacherId})\n` +
            `📚 Subject: ${subjectName}\n` +
            `❌ Denied by: ${ctx.from.first_name}\n` +
            `⏰ ${new Date().toLocaleString()}`,
            { parse_mode: "HTML" }
        );

        // Track activity
        await trackAdminActivity(ctx, 'subject_denied', {
            teacherId: teacher.teacherId,
            teacherName: teacher.name,
            subject: subjectName
        });

    } catch (error) {
        console.error('Error denying subject:', error);
        ctx.reply('❌ An error occurred while denying the subject.');
    }
});

// Handle close action
teacherMySubjectsScene.action('close_subjects', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('✅ Subjects menu closed.', teacherMenu);
    ctx.scene.leave();
});

// Handle add new subject action
teacherMySubjectsScene.action('add_new_subject', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('add_new_subject_scene');
});

// Handle edit subject name action
teacherMySubjectsScene.action('edit_subject_name', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('edit_subject_name_scene');
});

// Handle delete subject action
teacherMySubjectsScene.action('delete_subject', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('delete_subject_scene');
});

// Register all scenes
stage.register(teacherMySubjectsScene);
stage.register(addNewSubjectScene);
stage.register(editSubjectNameScene);
stage.register(deleteSubjectScene);

// Teacher My Students Scene
const teacherMyStudentsScene = new Scenes.BaseScene('teacher_my_students_scene');

teacherMyStudentsScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create main menu with view options
        ctx.reply(
            '👥 *My Students*\n\nHow would you like to view your students?',
            Markup.inlineKeyboard([
                [Markup.button.callback('📚 By Subject', 'view_by_subject')],
                [Markup.button.callback('🏫 By Class', 'view_by_class')],
                [Markup.button.callback('❌ Cancel', 'cancel_my_students')]
            ])
        );

    } catch (error) {
        console.error('Error in teacher my students scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle view by subject selection
teacherMyStudentsScene.action('view_by_subject', async (ctx) => {
    await ctx.answerCbQuery();
    
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `subject_students_${subject.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('⬅️ Back', 'back_to_my_students')]);

        ctx.reply('📚 Select a subject to view students:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error selecting view by subject:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle view by class selection
teacherMyStudentsScene.action('view_by_class', async (ctx) => {
    await ctx.answerCbQuery();
    
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get unique classes from teacher's students
        const classes = await TeacherStudent.distinct('className', {
            teacherId: teacher.teacherId
        });

        if (classes.length === 0) {
            ctx.reply('❌ You have no students in any classes.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create class buttons
        const classButtons = classes.map(className => 
            [Markup.button.callback(className, `class_students_${className.replace(/ /g, '_')}`)]
        );
        
        classButtons.push([Markup.button.callback('⬅️ Back', 'back_to_my_students')]);

        ctx.reply('🏫 Select a class to view students:', Markup.inlineKeyboard(classButtons));

    } catch (error) {
        console.error('Error selecting view by class:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject students selection
teacherMyStudentsScene.action(/^subject_students_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this subject
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1 });

        if (students.length === 0) {
            ctx.reply(`❌ No students found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Store data in session for pagination
        ctx.session.studentListView = {
            type: 'subject',
            identifier: subject,
            students: students,
            currentPage: 0,
            totalPages: Math.ceil(students.length / 10)
        };

        // Display first page
        await displayStudentList(ctx);

    } catch (error) {
        console.error('Error loading subject students:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle class students selection
teacherMyStudentsScene.action(/^class_students_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this class
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            className: className
        }).sort({ studentName: 1 });

        if (students.length === 0) {
            ctx.reply(`❌ No students found in ${className}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Store data in session for pagination
        ctx.session.studentListView = {
            type: 'class',
            identifier: className,
            students: students,
            currentPage: 0,
            totalPages: Math.ceil(students.length / 10)
        };

        // Display first page
        await displayStudentList(ctx);

    } catch (error) {
        console.error('Error loading class students:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Function to display student list with pagination
const displayStudentList = async (ctx) => {
    const { studentListView } = ctx.session;
    const { type, identifier, students, currentPage, totalPages } = studentListView;
    
    const startIndex = currentPage * 10;
    const endIndex = Math.min(startIndex + 10, students.length);
    const currentStudents = students.slice(startIndex, endIndex);
    
    // Create message header
    let message = `👥 *Students ${type === 'subject' ? 'in' : 'from'} ${identifier}*\n\n`;
    message += `📊 Total: ${students.length} students\n`;
    message += `📄 Page ${currentPage + 1} of ${totalPages}\n\n`;
    
    // Add student list
    currentStudents.forEach((student, index) => {
        const globalIndex = startIndex + index + 1;
        message += `${globalIndex}. ${student.studentName}\n`;
        message += `   🆔 ID: ${student.studentId}\n`;
        if (type === 'class') {
            message += `   📚 Subject: ${student.subject}\n`;
        } else {
            message += `   🏫 Class: ${student.className}\n`;
        }
        message += '\n';
    });
    
    // Create pagination buttons
    const paginationButtons = [];
    
    if (currentPage > 0) {
        paginationButtons.push(Markup.button.callback('⬅️ Previous', 'students_prev_page'));
    }
    
    if (currentPage < totalPages - 1) {
        paginationButtons.push(Markup.button.callback('Next ➡️', 'students_next_page'));
    }
    
    // Create action buttons
    const actionButtons = [
        [Markup.button.callback('🗑️ Remove This List', 'remove_student_list')],
        [Markup.button.callback('⬅️ Back to View Options', 'back_to_view_options')],
        [Markup.button.callback('❌ Close', 'close_student_list')]
    ];
    
    // Combine all buttons
    const allButtons = [];
    if (paginationButtons.length > 0) {
        allButtons.push(paginationButtons);
    }
    allButtons.push(...actionButtons);
    
    // Edit or send new message
    if (ctx.session.studentListMessageId) {
        try {
            await ctx.telegram.editMessageText(
                ctx.chat.id,
                ctx.session.studentListMessageId,
                null,
                message,
                {
                    parse_mode: 'HTML',
                    reply_markup: Markup.inlineKeyboard(allButtons).reply_markup
                }
            );
        } catch (error) {
            // If message can't be edited, send a new one
            const newMessage = await ctx.replyWithHTML(
                message,
                Markup.inlineKeyboard(allButtons)
            );
            ctx.session.studentListMessageId = newMessage.message_id;
        }
    } else {
        const newMessage = await ctx.replyWithHTML(
            message,
            Markup.inlineKeyboard(allButtons)
        );
        ctx.session.studentListMessageId = newMessage.message_id;
    }
};

// Handle pagination
teacherMyStudentsScene.action('students_prev_page', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.studentListView.currentPage--;
    await displayStudentList(ctx);
});

teacherMyStudentsScene.action('students_next_page', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.studentListView.currentPage++;
    await displayStudentList(ctx);
});

// Handle remove list confirmation
teacherMyStudentsScene.action('remove_student_list', async (ctx) => {
    await ctx.answerCbQuery();
    
    const { studentListView } = ctx.session;
    const { type, identifier } = studentListView;
    
    ctx.reply(
        `⚠️ *CONFIRM DELETION*\n\n` +
        `Are you sure you want to remove ALL students ${type === 'subject' ? 'from' : 'in'} ${identifier}?\n\n` +
        `*This action cannot be undone!*`,
        Markup.inlineKeyboard([
            [Markup.button.callback('✅ Yes, Remove All', 'confirm_remove_list')],
            [Markup.button.callback('❌ No, Cancel', 'cancel_remove_list')]
        ])
    );
});

// Handle list removal confirmation
teacherMyStudentsScene.action('confirm_remove_list', async (ctx) => {
    await ctx.answerCbQuery();
    
    try {
        const { studentListView } = ctx.session;
        const { type, identifier, students } = studentListView;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        let deleteCriteria;
        if (type === 'subject') {
            deleteCriteria = {
                teacherId: teacher.teacherId,
                subject: identifier
            };
        } else {
            deleteCriteria = {
                teacherId: teacher.teacherId,
                className: identifier
            };
        }
        
        // Delete all relationships
        const result = await TeacherStudent.deleteMany(deleteCriteria);
        
        // Delete message if exists
        if (ctx.session.studentListMessageId) {
            try {
                await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.studentListMessageId);
            } catch (error) {
                console.error('Error deleting message:', error);
            }
        }
        
        ctx.reply(
            `✅ Successfully removed ${result.deletedCount} students ${type === 'subject' ? 'from' : 'in'} ${identifier}.`,
            teacherMenu
        );
        
        // Clean up session
        delete ctx.session.studentListView;
        delete ctx.session.studentListMessageId;
        
    } catch (error) {
        console.error('Error removing student list:', error);
        ctx.reply('❌ An error occurred while removing the list.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Handle removal cancellation
teacherMyStudentsScene.action('cancel_remove_list', async (ctx) => {
    await ctx.answerCbQuery();
    // Return to the student list view
    await displayStudentList(ctx);
});

// Handle back to view options
teacherMyStudentsScene.action('back_to_view_options', async (ctx) => {
    await ctx.answerCbQuery();
    
    // Clean up session
    delete ctx.session.studentListView;
    if (ctx.session.studentListMessageId) {
        try {
            await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.studentListMessageId);
        } catch (error) {
            console.error('Error deleting message:', error);
        }
        delete ctx.session.studentListMessageId;
    }
    
    ctx.scene.reenter();
});

// Handle back to my students
teacherMyStudentsScene.action('back_to_my_students', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter();
});

// Handle close list
teacherMyStudentsScene.action('close_student_list', async (ctx) => {
    await ctx.answerCbQuery();
    
    // Clean up session
    delete ctx.session.studentListView;
    if (ctx.session.studentListMessageId) {
        try {
            await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.studentListMessageId);
        } catch (error) {
            console.error('Error deleting message:', error);
        }
        delete ctx.session.studentListMessageId;
    }
    
    ctx.reply('✅ Student list closed.', teacherMenu);
    ctx.scene.leave();
});

// Handle cancellation
teacherMyStudentsScene.action('cancel_my_students', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ My students view cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Register the scene
stage.register(teacherMyStudentsScene);

const parent_view_attendance_scene = new Scenes.BaseScene('parent_view_attendance_scene');

parent_view_attendance_scene.enter(async (ctx) => {
    try {
        const parent = await User.findOne({ telegramId: ctx.from.id, role: 'parent' });
        if (!parent) {
            ctx.reply('❌ You are not registered as a parent.', parentMenu);
            return ctx.scene.leave();
        }

        const students = await Student.find({ parentId: parent.telegramId });
        if (students.length === 0) {
            ctx.reply('❌ No students linked to your account.', parentMenu);
            return ctx.scene.leave();
        }

        let message = '📅 *Attendance Records*\n\n';

        for (const student of students) {
            message += `*Student: ${student.name} (${student.studentId})*\n`;
            message += `Class: ${student['class']}\n\n`;

            const attendances = await Attendance.find({
                "students.studentId": student.studentId
            }).sort({ date: -1 }).limit(5);

            if (attendances.length === 0) {
                message += 'No attendance records found.\n\n';
            } else {
                attendances.forEach((att, index) => {
                    const studentAtt = att.students.find(s => s.studentId === student.studentId);
                    const status = studentAtt ? studentAtt.status : 'unknown';
                    const emoji = status === 'present' ? '✅' : '❌';

                    message += `${index + 1}. ${att.date.toLocaleDateString()}\n`;
                    message += `   Subject: ${att.subject}\n`;
                    message += `   Status: ${emoji} ${status.charAt(0).toUpperCase() + status.slice(1)}\n\n`;
                });
            }

            message += '━━━━━━━━━━━━━━━━━━━━\n\n';
        }

        ctx.replyWithHTML(message, parentMenu);
        ctx.scene.leave();

    } catch (error) {
        console.error('Error in parent attendance scene:', error);
        ctx.reply('❌ An error occurred while fetching attendance records.', parentMenu);
        ctx.scene.leave();
    }
});

stage.register(parent_view_attendance_scene);




// Simple structured logger
const logger = {
    error: (message, meta = {}) => {
        console.log(JSON.stringify({
            level: 'error',
            timestamp: new Date().toISOString(),
            message,
            ...meta
        }));
    }
};

// Configurable limits
const RECORDS_PER_PAGE = parseInt(process.env.RECORDS_PER_PAGE) || 10;
const DAYS_LIMIT = parseInt(process.env.DAYS_LIMIT) || 30;
const SESSION_TIMEOUT_MS = parseInt(process.env.SESSION_TIMEOUT_MS) || 5 * 60 * 1000; // 5 minutes

const teacherAttendanceScene = new Scenes.BaseScene('teacher_attendance_scene');

// Session timeout middleware for attendance scene
const setAttendanceSessionTimeout = (ctx) => {
    if (ctx.session.attendanceTimeout) {
        clearTimeout(ctx.session.attendanceTimeout);
    }
    ctx.session.attendanceTimeout = setTimeout(() => {
        delete ctx.session.attendanceData;
        delete ctx.session.attendanceMessageId;
        logger.error('Attendance session timeout cleared', { chatId: ctx.chat?.id });
    }, SESSION_TIMEOUT_MS);
};

teacherAttendanceScene.enter(async (ctx) => {
    try {
        // Validate telegramId
        if (!ctx.from?.id || typeof ctx.from.id !== 'number') {
            logger.error('Invalid telegramId', { chatId: ctx.chat?.id, telegramId: ctx.from?.id });
            ctx.reply('❌ Invalid user ID. Please try again.', teacherMenu);
            return ctx.scene.leave();
        }

        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `attendance_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('📊 View Attendance Records', 'view_attendance_records')]);
        subjectButtons.push([Markup.button.callback('🔔 Attendance Reminders', 'attendance_reminders')]);
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_attendance')]);

        ctx.reply('📚 Select a subject to take attendance:', Markup.inlineKeyboard(subjectButtons));
        setAttendanceSessionTimeout(ctx);

    } catch (error) {
        logger.error('Error in teacher attendance scene', { error: error.message, telegramId: ctx.from?.id });
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection for attendance
teacherAttendanceScene.action(/^attendance_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this subject
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1 });

        if (students.length === 0) {
            ctx.reply(`❌ No students found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Store attendance data in session
        ctx.session.attendanceData = {
            subject: subject,
            className: students[0].className, // Assuming all students in same class
            students: students.map(student => ({
                studentId: student.studentId,
                studentName: student.studentName,
                status: 'present', // Default all present
                parentNotified: false
            })),
            date: new Date()
        };

        // Display attendance interface
        await displayAttendanceInterface(ctx);
        setAttendanceSessionTimeout(ctx);

    } catch (error) {
        logger.error('Error selecting subject for attendance', { error: error.message, telegramId: ctx.from?.id });
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Display attendance interface with student buttons
const displayAttendanceInterface = async (ctx) => {
    const { attendanceData } = ctx.session;
    const { students, subject, className, date } = attendanceData;
    
    let message = `📋 *Attendance for ${subject}*\n\n`;
    message += `🏫 Class: ${className}\n`;
    message += `📅 Date: ${date.toLocaleDateString()}\n\n`;
    message += `👥 Students: ${students.length}\n`;
    message += `✅ Present: ${students.filter(s => s.status === 'present').length}\n`;
    message += `❌ Absent: ${students.filter(s => s.status === 'absent').length}\n\n`;
    message += `Click on a student to mark them as absent:\n`;

    // Create student buttons (5 per row)
    const studentButtons = [];
    for (let i = 0; i < students.length; i += 5) {
        const row = students.slice(i, i + 5).map(student => {
            const emoji = student.status === 'present' ? '✅' : '❌';
            return Markup.button.callback(
                `${emoji} ${student.studentName.split(' ')[0]}`,
                `toggle_attendance_${student.studentId}`
            );
        });
        studentButtons.push(row);
    }

    // Add action buttons
    studentButtons.push(
        [Markup.button.callback('📤 Submit Attendance', 'submit_attendance')],
        [Markup.button.callback('🔄 Reset All', 'reset_attendance')],
        [Markup.button.callback('❌ Cancel', 'cancel_attendance')]
    );

    // Delete old message if exists
    if (ctx.session.attendanceMessageId) {
        try {
            await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.attendanceMessageId);
        } catch (error) {
            logger.error('Failed to delete old attendance message', { chatId: ctx.chat.id, messageId: ctx.session.attendanceMessageId, error: error.message });
        }
    }

    // Send new message
    const newMessage = await ctx.replyWithHTML(
        message,
        Markup.inlineKeyboard(studentButtons)
    );
    ctx.session.attendanceMessageId = newMessage.message_id;
    setAttendanceSessionTimeout(ctx);
};

// Handle student attendance toggling
teacherAttendanceScene.action(/^toggle_attendance_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const { attendanceData } = ctx.session;
        const studentIndex = attendanceData.students.findIndex(s => s.studentId === studentId);
        
        if (studentIndex !== -1) {
            // Toggle status
            attendanceData.students[studentIndex].status = 
                attendanceData.students[studentIndex].status === 'present' ? 'absent' : 'present';
            
            // Update session
            ctx.session.attendanceData = attendanceData;
            
            // Update display
            await displayAttendanceInterface(ctx);
            setAttendanceSessionTimeout(ctx);
        }
    } catch (error) {
        logger.error('Error toggling attendance', { error: error.message, telegramId: ctx.from?.id });
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
    }
});

// Handle attendance submission
teacherAttendanceScene.action('submit_attendance', async (ctx) => {
    await ctx.answerCbQuery();
    
    try {
        const { attendanceData } = ctx.session;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Generate unique attendance ID
        const attendanceId = await generateUniqueAttendanceId();
        
        // Count present and absent students
        const presentCount = attendanceData.students.filter(s => s.status === 'present').length;
        const absentCount = attendanceData.students.filter(s => s.status === 'absent').length;
        
        // Create attendance record
        const attendanceRecord = new Attendance({
            attendanceId: attendanceId,
            teacherId: teacher.teacherId,
            teacherName: teacher.name,
            subject: attendanceData.subject,
            className: attendanceData.className,
            date: attendanceData.date,
            students: attendanceData.students,
            totalStudents: attendanceData.students.length,
            presentCount: presentCount,
            absentCount: absentCount
        });
        
        await attendanceRecord.save();
        
        // Notify parents of absent students
        const absentStudents = attendanceData.students.filter(s => s.status === 'absent');
        let notifiedCount = 0;
        
        for (const student of absentStudents) {
            const studentRecord = await Student.findOne({ studentId: student.studentId });
            
            if (studentRecord && studentRecord.parentId) {
                try {
                    await ctx.telegram.sendMessage(
                        studentRecord.parentId,
                        `📢 *Attendance Notification*\n\n` +
                        `Your child *${student.studentName}* was marked *absent* from:\n` +
                        `📚 Subject: ${attendanceData.subject}\n` +
                        `🏫 Class: ${attendanceData.className}\n` +
                        `📅 Date: ${attendanceData.date.toLocaleDateString()}\n\n` +
                        `If this is an error, please contact the school.`,
                        { parse_mode: "HTML" }
                    );
                    
                    notifiedCount++;
                    // Update attendance record to mark parent notified
                    await Attendance.updateOne(
                        { attendanceId: attendanceId, "students.studentId": student.studentId },
                        { $set: { "students.$.parentNotified": true } }
                    );
                } catch (error) {
                    logger.error('Failed to notify parent', { studentId: student.studentId, error: error.message });
                }
            }
        }
        
        // Delete the attendance message
        if (ctx.session.attendanceMessageId) {
            try {
                await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.attendanceMessageId);
            } catch (error) {
                logger.error('Failed to delete attendance message on submit', { chatId: ctx.chat.id, messageId: ctx.session.attendanceMessageId, error: error.message });
            }
        }

        // Send confirmation message
        ctx.replyWithHTML(
            `✅ *Attendance Recorded Successfully!*\n\n` +
            `📚 Subject: ${attendanceData.subject}\n` +
            `🏫 Class: ${attendanceData.className}\n` +
            `📅 Date: ${attendanceData.date.toLocaleDateString()}\n\n` +
            `📊 Summary:\n` +
            `• Total Students: ${attendanceData.students.length}\n` +
            `• Present: ${presentCount}\n` +
            `• Absent: ${absentCount}\n` +
            `• Parents Notified: ${notifiedCount}\n\n` +
            `Attendance ID: ${attendanceId}`,
            teacherMenu
        );
        
        // Clean up session
        delete ctx.session.attendanceData;
        delete ctx.session.attendanceMessageId;
        clearTimeout(ctx.session.attendanceTimeout);
        
    } catch (error) {
        logger.error('Error submitting attendance', { error: error.message, telegramId: ctx.from?.id });
        ctx.reply('❌ An error occurred while recording attendance.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Handle attendance reset
teacherAttendanceScene.action('reset_attendance', async (ctx) => {
    await ctx.answerCbQuery();
    
    try {
        const { attendanceData } = ctx.session;
        
        // Reset all students to present
        attendanceData.students.forEach(student => {
            student.status = 'present';
            student.parentNotified = false;
        });
        
        // Update session
        ctx.session.attendanceData = attendanceData;
        
        // Update display
        await displayAttendanceInterface(ctx);
        setAttendanceSessionTimeout(ctx);
        
    } catch (error) {
        logger.error('Error resetting attendance', { error: error.message, telegramId: ctx.from?.id });
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
    }
});

// Handle attendance cancellation
teacherAttendanceScene.action('cancel_attendance', async (ctx) => {
    await ctx.answerCbQuery();
    
    // Delete the attendance message
    if (ctx.session.attendanceMessageId) {
        try {
            await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.attendanceMessageId);
        } catch (error) {
            logger.error('Failed to delete attendance message on cancel', { chatId: ctx.chat.id, messageId: ctx.session.attendanceMessageId, error: error.message });
        }
    }

    ctx.reply('❌ Attendance recording cancelled.', teacherMenu);
    delete ctx.session.attendanceData;
    delete ctx.session.attendanceMessageId;
    clearTimeout(ctx.session.attendanceTimeout);
    ctx.scene.leave();
});

// View Attendance Records Scene
teacherAttendanceScene.action('view_attendance_records', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('view_attendance_records_scene');
});

// Attendance Reminders Scene
teacherAttendanceScene.action('attendance_reminders', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('attendance_reminders_scene');
});

// View Attendance Records Scene
const viewAttendanceRecordsScene = new Scenes.BaseScene('view_attendance_records_scene');

// Session timeout middleware for records scene
const setRecordsSessionTimeout = (ctx) => {
    if (ctx.session.recordsTimeout) {
        clearTimeout(ctx.session.recordsTimeout);
    }
    ctx.session.recordsTimeout = setTimeout(() => {
        delete ctx.session.recordsMessageId;
        delete ctx.session.recordsPage;
        logger.error('Records session timeout cleared', { chatId: ctx.chat?.id });
    }, SESSION_TIMEOUT_MS);
};

viewAttendanceRecordsScene.enter(async (ctx) => {
    // Validate telegramId
    if (!ctx.from?.id || typeof ctx.from.id !== 'number') {
        logger.error('Invalid telegramId', { chatId: ctx.chat?.id, telegramId: ctx.from?.id });
        ctx.reply('❌ Invalid user ID. Please try again.', teacherMenu);
        return ctx.scene.leave();
    }

    setRecordsSessionTimeout(ctx);
    await displayAttendanceRecords(ctx, 1);
});

const displayAttendanceRecords = async (ctx, page = 1) => {
    try {
        // Validate teacher
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher) {
            logger.error('Teacher not found', { telegramId: ctx.from.id });
            ctx.reply('❌ Teacher not found. Please register first.', teacherMenu);
            return ctx.scene.leave();
        }

        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - DAYS_LIMIT);

        // Get total count for pagination
        const totalRecords = await Attendance.countDocuments({
            teacherId: teacher.teacherId,
            date: { $gte: thirtyDaysAgo }
        });

        // Get paginated records
        const records = await Attendance.find({
            teacherId: teacher.teacherId,
            date: { $gte: thirtyDaysAgo }
        })
            .sort({ date: -1 })
            .skip((page - 1) * RECORDS_PER_PAGE)
            .limit(RECORDS_PER_PAGE);

        if (records.length === 0) {
            // Clean up old message if exists
            if (ctx.session.recordsMessageId) {
                try {
                    await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.recordsMessageId);
                } catch (error) {
                    logger.error('Failed to delete old records message', { chatId: ctx.chat.id, messageId: ctx.session.recordsMessageId, error: error.message });
                }
                delete ctx.session.recordsMessageId;
            }
            ctx.reply(`📊 No attendance records found for the last ${DAYS_LIMIT} days.`, teacherMenu);
            return ctx.scene.leave();
        }

        let message = `📊 *Recent Attendance Records (Page ${page})*\n\n`;
        
        records.forEach((record, index) => {
            const absentStudents = record.students
                .filter(student => student.status === 'absent')
                .map(student => student.studentName)
                .join(', ') || 'None';
            
            message += `*${(page - 1) * RECORDS_PER_PAGE + index + 1}. ${record.subject}*\n`;
            message += `   📅 ${record.date.toLocaleDateString()}\n`;
            message += `   👥 Students: ${record.totalStudents}\n`;
            message += `   ✅ Present: ${record.presentCount}\n`;
            message += `   ❌ Absent: ${record.absentCount}\n`;
            message += `   🔔 Absent Students: ${absentStudents}\n\n`;
        });

        // Create pagination and action buttons
        const paginationButtons = [];
        if (page > 1) {
            paginationButtons.push(Markup.button.callback('⬅️ Previous', `records_page_${page - 1}`));
        }
        if (page * RECORDS_PER_PAGE < totalRecords) {
            paginationButtons.push(Markup.button.callback('Next ➡️', `records_page_${page + 1}`));
        }
        const actionButtons = [
            Markup.button.callback('📥 Export Attendance', 'export_attendance')
        ];
        const keyboard = paginationButtons.length > 0 
            ? Markup.inlineKeyboard([
                paginationButtons,
                actionButtons,
                [Markup.button.callback('❌ Cancel', 'cancel_records')]
            ])
            : Markup.inlineKeyboard([
                actionButtons,
                [Markup.button.callback('❌ Cancel', 'cancel_records')]
            ]);

        // Delete old message if exists
        if (ctx.session.recordsMessageId) {
            try {
                await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.recordsMessageId);
            } catch (error) {
                logger.error('Failed to delete old records message', { chatId: ctx.chat.id, messageId: ctx.session.recordsMessageId, error: error.message });
            }
        }

        // Send new message
        const newMessage = await ctx.replyWithHTML(message, keyboard);
        ctx.session.recordsMessageId = newMessage.message_id;
        ctx.session.recordsPage = page;

        setRecordsSessionTimeout(ctx);

    } catch (error) {
        logger.error('Error viewing attendance records', { error: error.message, telegramId: ctx.from.id, page });
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
};

// Handle pagination
viewAttendanceRecordsScene.action(/^records_page_(\d+)$/, async (ctx) => {
    const page = parseInt(ctx.match[1]);
    if (isNaN(page) || page < 1) {
        logger.error('Invalid page number', { chatId: ctx.chat.id, page });
        ctx.reply('❌ Invalid page number.', teacherMenu);
        return ctx.scene.leave();
    }

    await ctx.answerCbQuery();
    setRecordsSessionTimeout(ctx);
    await displayAttendanceRecords(ctx, page);
});

// Handle export attendance
viewAttendanceRecordsScene.action('export_attendance', async (ctx) => {
    await ctx.answerCbQuery();
    
    // Delete old message if exists
    if (ctx.session.recordsMessageId) {
        try {
            await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.recordsMessageId);
        } catch (error) {
            logger.error('Failed to delete records message on export', { chatId: ctx.chat.id, messageId: ctx.session.recordsMessageId, error: error.message });
        }
        delete ctx.session.recordsMessageId;
    }

    // Send confirmation message
    const confirmMessage = await ctx.replyWithHTML(
        '📥 *Export Attendance Records*\n\n' +
        'This will export all attendance records for the last 30 days as a text file.\n' +
        'Would you like to proceed?',
        Markup.inlineKeyboard([
            [Markup.button.callback('✅ Yes, Export', 'confirm_export')],
            [Markup.button.callback('❌ Cancel', 'cancel_records')]
        ])
    );
    ctx.session.recordsMessageId = confirmMessage.message_id;
    setRecordsSessionTimeout(ctx);
});

// Handle export confirmation
viewAttendanceRecordsScene.action('confirm_export', async (ctx) => {
    await ctx.answerCbQuery();
    
    try {
        // Delete confirmation message
        if (ctx.session.recordsMessageId) {
            try {
                await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.recordsMessageId);
            } catch (error) {
                logger.error('Failed to delete confirmation message', { chatId: ctx.chat.id, messageId: ctx.session.recordsMessageId, error: error.message });
            }
            delete ctx.session.recordsMessageId;
        }

        // Send progress message
        const progressMessage = await ctx.reply('⏳ Generating attendance export file...');
        
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher) {
            logger.error('Teacher not found for export', { telegramId: ctx.from.id });
            await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);
            ctx.reply('❌ Teacher not found. Please register first.', teacherMenu);
            return ctx.scene.leave();
        }

        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - DAYS_LIMIT);

        // Fetch all records for export
        const records = await Attendance.find({
            teacherId: teacher.teacherId,
            date: { $gte: thirtyDaysAgo }
        }).sort({ date: -1 });

        if (records.length === 0) {
            await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);
            ctx.reply(`📊 No attendance records found for the last ${DAYS_LIMIT} days.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Generate formatted text file content
        let fileContent = `====================================\n`;
        fileContent += `      Attendance Records Export\n`;
        fileContent += `====================================\n`;
        fileContent += `Teacher: ${teacher.name}\n`;
        fileContent += `Exported on: ${new Date().toLocaleString('en-US', { timeZone: 'Africa/Nairobi' })}\n`;
        fileContent += `Records from last ${DAYS_LIMIT} days\n`;
        fileContent += `====================================\n\n`;

        records.forEach((record, index) => {
            const absentStudents = record.students
                .filter(student => student.status === 'absent')
                .map(student => student.studentName)
                .join(', ') || 'None';
            
            fileContent += `Record ${index + 1}: ${record.subject}\n`;
            fileContent += `----------------------------------------\n`;
            fileContent += `Date: ${record.date.toLocaleDateString()}\n`;
            fileContent += `Class: ${record.className}\n`;
            fileContent += `Total Students: ${record.totalStudents}\n`;
            fileContent += `Present: ${record.presentCount}\n`;
            fileContent += `Absent: ${record.absentCount}\n`;
            fileContent += `Absent Students: ${absentStudents}\n`;
            fileContent += `----------------------------------------\n\n`;
        });

        fileContent += `====================================\n`;
        fileContent += `End of Export\n`;
        fileContent += `====================================\n`;

        // Create Buffer for text file
        const fileBuffer = Buffer.from(fileContent, 'utf-8');
        const fileName = `attendance_export_${new Date().toISOString().split('T')[0]}.txt`;

        // Send the file
        await ctx.telegram.sendDocument(
            ctx.chat.id,
            { source: fileBuffer, filename: fileName },
            { caption: `📥 *Attendance Records Exported*\n\nRecords from the last ${DAYS_LIMIT} days have been exported.` }
        );

        // Delete progress message
        await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);

        // Return to records view
        await displayAttendanceRecords(ctx, ctx.session.recordsPage || 1);
        setRecordsSessionTimeout(ctx);

    } catch (error) {
        logger.error('Error exporting attendance records', { error: error.message, telegramId: ctx.from.id });
        ctx.reply('❌ An error occurred while exporting records. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle cancellation
viewAttendanceRecordsScene.action('cancel_records', async (ctx) => {
    await ctx.answerCbQuery();
    
    // Clean up old message
    if (ctx.session.recordsMessageId) {
        try {
            await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.recordsMessageId);
        } catch (error) {
            logger.error('Failed to delete records message on cancel', { chatId: ctx.chat.id, messageId: ctx.session.recordsMessageId, error: error.message });
        }
    }

    ctx.reply('❌ Attendance records view cancelled.', teacherMenu);
    delete ctx.session.recordsMessageId;
    delete ctx.session.recordsPage;
    clearTimeout(ctx.session.recordsTimeout);
    ctx.scene.leave();
});

// Attendance Reminders Scene
const attendanceRemindersScene = new Scenes.BaseScene('attendance_reminders_scene');

// Session timeout middleware for reminders scene
const setRemindersSessionTimeout = (ctx) => {
    if (ctx.session.remindersTimeout) {
        clearTimeout(ctx.session.remindersTimeout);
    }
    ctx.session.remindersTimeout = setTimeout(() => {
        delete ctx.session.remindersMessageId;
        logger.error('Reminders session timeout cleared', { chatId: ctx.chat?.id });
    }, SESSION_TIMEOUT_MS);
};

attendanceRemindersScene.enter(async (ctx) => {
    // Validate telegramId
    if (!ctx.from?.id || typeof ctx.from.id !== 'number') {
        logger.error('Invalid telegramId', { chatId: ctx.chat?.id, telegramId: ctx.from?.id });
        ctx.reply('❌ Invalid user ID. Please try again.', teacherMenu);
        return ctx.scene.leave();
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher) {
            logger.error('Teacher not found', { telegramId: ctx.from.id });
            ctx.reply('❌ Teacher not found. Please register first.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons for reminders
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `reminder_subject_${subject.replace(/ /g, '_')}`)]
        );
        subjectButtons.push([Markup.button.callback('📋 View All Reminders', 'view_reminders')]);
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_reminders')]);

        // Delete old message if exists
        if (ctx.session.remindersMessageId) {
            try {
                await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.remindersMessageId);
            } catch (error) {
                logger.error('Failed to delete old reminders message', { chatId: ctx.chat.id, messageId: ctx.session.remindersMessageId, error: error.message });
            }
        }

        // Send new message
        const newMessage = await ctx.replyWithHTML(
            '🔔 *Attendance Reminders*\n\nSelect a subject to set a reminder or view all reminders:',
            Markup.inlineKeyboard(subjectButtons)
        );
        ctx.session.remindersMessageId = newMessage.message_id;
        setRemindersSessionTimeout(ctx);

    } catch (error) {
        logger.error('Error in attendance reminders scene', { error: error.message, telegramId: ctx.from?.id });
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection for setting reminders
attendanceRemindersScene.action(/^reminder_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher) {
            logger.error('Teacher not found for reminder', { telegramId: ctx.from.id });
            ctx.reply('❌ Teacher not found. Please register first.', teacherMenu);
            return ctx.scene.leave();
        }

        // Get students for this subject to find class
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1 });

        if (students.length === 0) {
            ctx.reply(`❌ No students found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        const className = students[0].className; // Assuming all students in same class

        // Delete old message
        if (ctx.session.remindersMessageId) {
            try {
                await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.remindersMessageId);
            } catch (error) {
                logger.error('Failed to delete reminders message', { chatId: ctx.chat.id, messageId: ctx.session.remindersMessageId, error: error.message });
            }
        }

        // Send confirmation for reminder
        const confirmMessage = await ctx.replyWithHTML(
            `🔔 *Set Attendance Reminder*\n\n` +
            `Subject: ${subject}\n` +
            `Class: ${className}\n\n` +
            `Send a reminder to all parents for the next class?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Send Reminder', `send_reminder_${subject.replace(/ /g, '_')}_${className.replace(/ /g, '_')}`)],
                [Markup.button.callback('❌ Cancel', 'cancel_reminders')]
            ])
        );
        ctx.session.remindersMessageId = confirmMessage.message_id;
        setRemindersSessionTimeout(ctx);

    } catch (error) {
        logger.error('Error selecting subject for reminder', { error: error.message, telegramId: ctx.from?.id });
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle sending reminder
attendanceRemindersScene.action(/^send_reminder_(.+)_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    const className = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher) {
            logger.error('Teacher not found for sending reminder', { telegramId: ctx.from.id });
            ctx.reply('❌ Teacher not found. Please register first.', teacherMenu);
            return ctx.scene.leave();
        }

        // Get students for this subject and class
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject,
            className: className
        });

        if (students.length === 0) {
            ctx.reply(`❌ No students found for ${subject} in ${className}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Delete old message
        if (ctx.session.remindersMessageId) {
            try {
                await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.remindersMessageId);
            } catch (error) {
                logger.error('Failed to delete reminders message on send', { chatId: ctx.chat.id, messageId: ctx.session.remindersMessageId, error: error.message });
            }
        }

        // Send progress message
        const progressMessage = await ctx.reply('⏳ Sending attendance reminders...');

        let notifiedCount = 0;
        for (const student of students) {
            const studentRecord = await Student.findOne({ studentId: student.studentId });
            if (studentRecord && studentRecord.parentId) {
                try {
                    await ctx.telegram.sendMessage(
                        studentRecord.parentId,
                        `🔔 *Attendance Reminder*\n\n` +
                        `Dear Parent,\n` +
                        `Please ensure your child, ${student.studentName}, attends the upcoming ${subject} class for ${className}.\n` +
                        `📅 Date: ${new Date().toLocaleDateString()}\n` +
                        `If you have any questions, contact the school.`,
                        { parse_mode: "HTML" }
                    );
                    notifiedCount++;
                } catch (error) {
                    logger.error('Failed to send reminder to parent', { studentId: student.studentId, error: error.message });
                }
            }
        }

        // Delete progress message
        await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);

        // Send confirmation
        ctx.replyWithHTML(
            `✅ *Reminders Sent Successfully!*\n\n` +
            `📚 Subject: ${subject}\n` +
            `🏫 Class: ${className}\n` +
            `📬 Parents Notified: ${notifiedCount}/${students.length}`,
            teacherMenu
        );

        // Clean up session
        delete ctx.session.remindersMessageId;
        clearTimeout(ctx.session.remindersTimeout);
        ctx.scene.leave();

    } catch (error) {
        logger.error('Error sending reminders', { error: error.message, telegramId: ctx.from?.id });
        ctx.reply('❌ An error occurred while sending reminders. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle view reminders
attendanceRemindersScene.action('view_reminders', async (ctx) => {
    await ctx.answerCbQuery();
    
    // For simplicity, assume no stored reminders; show placeholder
    try {
        // Delete old message
        if (ctx.session.remindersMessageId) {
            try {
                await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.remindersMessageId);
            } catch (error) {
                logger.error('Failed to delete reminders message on view', { chatId: ctx.chat.id, messageId: ctx.session.remindersMessageId, error: error.message });
            }
        }

        const message = await ctx.replyWithHTML(
            '🔔 *Attendance Reminders*\n\n' +
            'No reminders are currently scheduled.\n' +
            'Select a subject to set a new reminder.',
            Markup.inlineKeyboard([
                [Markup.button.callback('🔙 Back', 'back_to_reminders')],
                [Markup.button.callback('❌ Cancel', 'cancel_reminders')]
            ])
        );
        ctx.session.remindersMessageId = message.message_id;
        setRemindersSessionTimeout(ctx);

    } catch (error) {
        logger.error('Error viewing reminders', { error: error.message, telegramId: ctx.from?.id });
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle back to reminders
attendanceRemindersScene.action('back_to_reminders', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('attendance_reminders_scene');
});

// Handle cancellation
attendanceRemindersScene.action('cancel_reminders', async (ctx) => {
    await ctx.answerCbQuery();
    
    // Delete old message
    if (ctx.session.remindersMessageId) {
        try {
            await ctx.telegram.deleteMessage(ctx.chat.id, ctx.session.remindersMessageId);
        } catch (error) {
            logger.error('Failed to delete reminders message on cancel', { chatId: ctx.chat.id, messageId: ctx.session.remindersMessageId, error: error.message });
        }
    }

    ctx.reply('❌ Attendance reminders cancelled.', teacherMenu);
    delete ctx.session.remindersMessageId;
    clearTimeout(ctx.session.remindersTimeout);
    ctx.scene.leave();
});

// Register the scenes
stage.register(teacherAttendanceScene);
stage.register(viewAttendanceRecordsScene);
stage.register(attendanceRemindersScene);


// Admin Search Scene
const adminSearchScene = new Scenes.BaseScene('admin_search_scene');

adminSearchScene.enter(async (ctx) => {
    try {
        await trackAdminActivity(ctx, 'admin_search_initiated');
        
        ctx.reply(
            '🔍 *Admin Search System*\n\n' +
            'Select what you want to search:',
            Markup.inlineKeyboard([
                [Markup.button.callback('👨‍🏫 Teachers', 'search_teachers')],
                [Markup.button.callback('👨‍👩‍👧‍👦 Parents', 'search_parents')],
                [Markup.button.callback('👨‍🎓 Students', 'search_students')],
                [Markup.button.callback('❌ Cancel', 'cancel_search')]
            ])
        );
    } catch (error) {
        console.error('Error in admin search scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', adminMenu);
        ctx.scene.leave();
    }
});

// Handle search category selection
adminSearchScene.action(/^search_(teachers|parents|students)$/, async (ctx) => {
    const category = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        ctx.session.searchCategory = category;
        ctx.session.searchPage = 0;
        ctx.session.searchQuery = '';
        ctx.session.searchResults = [];
        
        ctx.reply(
            `🔍 Searching ${category}:\n\n` +
            'Please enter a name or ID to search. For names, type the starting letter(s).',
            Markup.keyboard([['❌ Cancel Search']]).resize()
        );
        
        // Switch to text input handling
        ctx.scene.enter('admin_search_input_scene');
    } catch (error) {
        console.error('Error selecting search category:', error);
        ctx.reply('❌ An error occurred. Please try again.', adminMenu);
        ctx.scene.leave();
    }
});

// Handle search cancellation
adminSearchScene.action('cancel_search', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Search cancelled.', adminMenu);
    ctx.scene.leave();
});

// Search Input Scene
const adminSearchInputScene = new Scenes.BaseScene('admin_search_input_scene');

adminSearchInputScene.enter((ctx) => {
    // Already set up in previous scene
});

adminSearchInputScene.on('text', async (ctx) => {
    const query = ctx.message.text.trim();
    
    if (query === '❌ Cancel Search') {
        ctx.reply('❌ Search cancelled.', adminMenu);
        delete ctx.session.searchCategory;
        delete ctx.session.searchQuery;
        delete ctx.session.searchResults;
        delete ctx.session.searchPage;
        return ctx.scene.leave();
    }
    
    if (!query) {
        ctx.reply('❌ Please enter a search query.');
        return;
    }
    
    try {
        ctx.session.searchQuery = query;
        ctx.session.searchPage = 0;
        
        // Perform search based on category
        let results = [];
        const searchRegex = new RegExp(`^${query}`, 'i');
        
        switch (ctx.session.searchCategory) {
            case 'teachers':
                // Search by ID or name starting with query
                results = await Teacher.find({
                    $or: [
                        { teacherId: { $regex: searchRegex } },
                        { name: { $regex: searchRegex } }
                    ]
                }).sort({ name: 1 });
                break;
                
            case 'parents':
                // Search parents (users with parent role)
                results = await User.find({
                    role: 'parent',
                    $or: [
                        { telegramId: { $regex: searchRegex } },
                        { name: { $regex: searchRegex } }
                    ]
                }).sort({ name: 1 });
                break;
                
            case 'students':
                // Search students by ID or name starting with query
                results = await Student.find({
                    $or: [
                        { studentId: { $regex: searchRegex } },
                        { name: { $regex: searchRegex } }
                    ]
                }).sort({ name: 1 });
                break;
        }
        
        ctx.session.searchResults = results;
        
        if (results.length === 0) {
            ctx.reply(
                `❌ No ${ctx.session.searchCategory} found matching "${query}".\n\n` +
                'Please try a different search term.',
                Markup.keyboard([['❌ Cancel Search']]).resize()
            );
            return;
        }
        
        // Display first page of results
        await displaySearchResults0(ctx);
        
    } catch (error) {
        console.error('Error performing search:', error);
        ctx.reply('❌ An error occurred during search. Please try again.', adminMenu);
        ctx.scene.leave();
    }
});

// Function to display search results with pagination
const displaySearchResults0 = async (ctx) => {
    const { searchResults, searchPage, searchCategory, searchQuery } = ctx.session;
    const totalPages = Math.ceil(searchResults.length / 10);
    const startIdx = searchPage * 10;
    const endIdx = Math.min(startIdx + 10, searchResults.length);
    const currentResults = searchResults.slice(startIdx, endIdx);
    
    let message = `🔍 *Search Results for "${searchQuery}"*\n\n`;
    message += `📋 Category: ${searchCategory}\n`;
    message += `📊 Results: ${searchResults.length} found\n`;
    message += `📄 Page ${searchPage + 1} of ${totalPages}\n\n`;
    
    // Add result details based on category
    currentResults.forEach((result, index) => {
        const globalIndex = startIdx + index + 1;
        
        switch (searchCategory) {
            case 'teachers':
                message += `${globalIndex}. *${result.name}*\n`;
                message += `   🆔 ID: ${result.teacherId}\n`;
                message += `   📚 Subjects: ${result.subjects?.join(', ') || 'None'}\n`;
                message += `   📱 Telegram: ${result.telegramId || 'Not linked'}\n\n`;
                break;
                
            case 'parents':
                message += `${globalIndex}. *${result.name}*\n`;
                message += `   🆔 ID: ${result.telegramId}\n`;
                message += `   👥 Students: ${result.studentIds?.length || 0}\n`;
                if (result.username) {
                    message += `   👤 Username: @${result.username}\n`;
                }
                message += '\n';
                break;
                
            case 'students':
                message += `${globalIndex}. *${result.name}*\n`;
                message += `   🆔 ID: ${result.studentId}\n`;
                message += `   🏫 Class: ${result.class}\n`;
                message += `   👪 Parent: ${result.parentId ? 'Linked' : 'Not linked'}\n\n`;
                break;
        }
    });
    
    // Create pagination buttons
    const paginationButtons = [];
    
    if (searchPage > 0) {
        paginationButtons.push(Markup.button.callback('⬅️ Previous', 'search_prev_page'));
    }
    
    if (searchPage < totalPages - 1) {
        paginationButtons.push(Markup.button.callback('Next ➡️', 'search_next_page'));
    }
    
    // Create action buttons
    const actionButtons = [
        [Markup.button.callback('🔄 New Search', 'search_new')],
        [Markup.button.callback('✅ Done', 'search_done')]
    ];
    
    if (paginationButtons.length > 0) {
        actionButtons.unshift(paginationButtons);
    }
    
    // Edit or send new message
    if (ctx.session.searchMessageId) {
        try {
            await ctx.telegram.editMessageText(
                ctx.chat.id,
                ctx.session.searchMessageId,
                null,
                message,
                {
                    parse_mode: 'HTML',
                    reply_markup: Markup.inlineKeyboard(actionButtons).reply_markup
                }
            );
        } catch (error) {
            // If message can't be edited, send a new one
            const newMessage = await ctx.replyWithHTML(
                message,
                Markup.inlineKeyboard(actionButtons)
            );
            ctx.session.searchMessageId = newMessage.message_id;
        }
    } else {
        const newMessage = await ctx.replyWithHTML(
            message,
            Markup.inlineKeyboard(actionButtons)
        );
        ctx.session.searchMessageId = newMessage.message_id;
    }
};

// Handle pagination in search results
adminSearchInputScene.action('search_prev_page', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.searchPage--;
    await displaySearchResults0(ctx);
});

adminSearchInputScene.action('search_next_page', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.searchPage++;
    await displaySearchResults0(ctx);
});

adminSearchInputScene.action('search_new', async (ctx) => {
    await ctx.answerCbQuery();
    delete ctx.session.searchMessageId;
    ctx.scene.enter('admin_search_scene');
});

adminSearchInputScene.action('search_done', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('✅ Search completed.', adminMenu);
    delete ctx.session.searchCategory;
    delete ctx.session.searchQuery;
    delete ctx.session.searchResults;
    delete ctx.session.searchPage;
    delete ctx.session.searchMessageId;
    ctx.scene.leave();
});

// Register the scenes
stage.register(adminSearchScene);
stage.register(adminSearchInputScene);


// --- Remove Student Scene ---
const removeStudentScene = new Scenes.BaseScene('remove_student_scene');

removeStudentScene.enter(async (ctx) => {
    try {
        // Track admin activity
        await trackAdminActivity(ctx, 'remove_student_initiated');
        
        // Notify master admin
        await notifyMasterAdmin(ctx, 'remove_student_initiated', {
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id
        });
        
        // Replace admin menu with cancel button in keyboard
        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel']
        ]).oneTime().resize();
        
        await ctx.reply(
            '➖ Enter the Student ID (format: STXXXX) to remove:',
            cancelKeyboard
        );
    } catch (error) {
        console.error('Error entering remove student scene:', error);
        await trackAdminActivity(ctx, 'remove_student_error', { error: error.message });
        await notifyMasterAdmin(ctx, 'remove_student_error', { 
            error: error.message,
            adminId: ctx.from.id
        });
        await ctx.reply('❌ An error occurred.', adminMenu);
        await ctx.scene.leave();
    }
});

// Handle student ID input and cancel command
removeStudentScene.on('text', async (ctx) => {
    const input = ctx.message.text.trim();
    
    // Check for cancel command
    if (input === '❌ Cancel') {
        await trackAdminActivity(ctx, 'remove_student_cancelled');
        await notifyMasterAdmin(ctx, 'remove_student_cancelled', { 
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id
        });
        await ctx.reply('❌ Student removal cancelled.', adminMenu);
        delete ctx.session.studentToRemove;
        return ctx.scene.leave();
    }
    
    // Check if input is a valid student ID
    if (!isValidStudentId(input)) {
        return ctx.reply('❌ Invalid Student ID format. Please enter a valid ID (e.g., ST1234) or select "❌ Cancel".');
    }
    
    try {
        const student = await getStudentById(input);
        if (!student) {
            await ctx.reply('❌ Student not found with this ID.', adminMenu);
            return ctx.scene.leave();
        }
        
        // Store student ID in session for confirmation
        ctx.session.studentToRemove = student.studentId;
        
        // Get additional details for confirmation
        const parent = student.parentId ? await getUserById(student.parentId) : null;
        const teacherRelations = await TeacherStudent.find({ studentId: student.studentId });
        const grades = await Grade.find({ studentId: student.studentId });
        
        let confirmMessage = `⚠️ *CONFIRM STUDENT REMOVAL*\n\n` +
            `👤 Name: ${student.name}\n` +
            `🆔 ID: ${student.studentId}\n` +
            `🏫 Class: ${student.class}\n` +
            `👪 Parent: ${parent ? parent.name : 'None'}\n` +
            `📚 Teacher Relationships: ${teacherRelations.length}\n` +
            `💯 Grades: ${grades.length}\n\n` +
            `*This will permanently delete:*\n` +
            `• The student record\n` +
            `• All linked grades\n` +
            `• All teacher relationships\n` +
            `• Unlink from parent if applicable\n\n` +
            `*This action cannot be undone!*\n\n` +
            `Type CONFIRM to proceed or select "❌ Cancel":`;
        
        // Keep cancel button in keyboard for confirmation step
        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel']
        ]).oneTime().resize();
        
        await ctx.replyWithHTML(confirmMessage, cancelKeyboard);
        
    } catch (error) {
        console.error('Error preparing student removal:', error);
        await trackAdminActivity(ctx, 'remove_student_preparation_error', { 
            studentId: input,
            error: error.message 
        });
        
        await ctx.reply('❌ An error occurred.', adminMenu);
        delete ctx.session.studentToRemove;
        await ctx.scene.leave();
    }
});

// Handle confirmation after ID is provided
removeStudentScene.on('text', async (ctx) => {
    const input = ctx.message.text.trim().toUpperCase();
    const studentId = ctx.session.studentToRemove;
    
    if (!studentId) {
        await ctx.reply('❌ No student selected. Please start over.', adminMenu);
        return ctx.scene.leave();
    }
    
    if (input === '❌ CANCEL') {
        await trackAdminActivity(ctx, 'remove_student_cancelled', { studentId });
        await notifyMasterAdmin(ctx, 'remove_student_cancelled', { 
            studentId,
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id
        });
        await ctx.reply('❌ Student removal cancelled.', adminMenu);
        delete ctx.session.studentToRemove;
        return ctx.scene.leave();
    }
    
    if (input !== 'CONFIRM') {
        return ctx.reply('❌ Please type CONFIRM to proceed or select "❌ Cancel".');
    }
    
    try {
        // Track removal start
        await trackAdminActivity(ctx, 'remove_student_started', { studentId });
        const masterAdminMsg = await notifyMasterAdmin(ctx, 'remove_student_started', { 
            studentId,
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id
        });
        
        const student = await getStudentById(studentId);
        if (!student) {
            await ctx.reply('❌ Student not found.', adminMenu);
            delete ctx.session.studentToRemove;
            return ctx.scene.leave();
        }
        
        // Unlink parent if exists
        let unlinkedParent = false;
        if (student.parentId) {
            const parent = await getUserById(student.parentId);
            if (parent) {
                parent.studentIds = parent.studentIds.filter(id => id !== studentId);
                if (parent.studentIds.length === 0) {
                    parent.role = 'user';
                    await trackAdminActivity(ctx, 'parent_demoted_to_user', {
                        parentId: parent.telegramId,
                        parentName: parent.name
                    });
                }
                await parent.save();
                unlinkedParent = true;
                
                await trackAdminActivity(ctx, 'parent_unlinked', {
                    studentId: student.studentId,
                    studentName: student.name,
                    parentId: parent.telegramId,
                    parentName: parent.name
                });
            }
        }
        
        // Delete teacher relationships
        const teacherRelations = await TeacherStudent.find({ studentId: studentId });
        for (const relation of teacherRelations) {
            await trackAdminActivity(ctx, 'teacher_relation_deleted', {
                teacherId: relation.teacherId,
                teacherName: relation.teacherName,
                studentId: relation.studentId,
                studentName: relation.studentName,
                subject: relation.subject,
                className: relation.className
            });
        }
        await TeacherStudent.deleteMany({ studentId: studentId });
        
        // Delete grades
        await Grade.deleteMany({ studentId: studentId });
        
        // Delete student
        await Student.deleteOne({ studentId: studentId });
        
        await trackAdminActivity(ctx, 'student_deleted', {
            studentId: student.studentId,
            studentName: student.name,
            className: student.class
        });
        
        // Notify completion
        await notifyMasterAdmin(ctx, 'remove_student_completed', {
            studentId,
            studentName: student.name,
            unlinkedParent: unlinkedParent ? 'Yes' : 'No',
            deletedRelations: teacherRelations.length,
            deletedGrades: await Grade.countDocuments({ studentId: studentId }), // Should be 0 after deletion
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id
        }, masterAdminMsg?.message_id);
        
        await ctx.reply(
            `✅ Student removed successfully!\n` +
            `👤 Name: ${student.name}\n` +
            `�ID: ${studentId}\n` +
            `👪 Parent Unlinked: ${unlinkedParent ? 'Yes' : 'No'}\n` +
            `📚 Relationships Removed: ${teacherRelations.length}\n` +
            `💯 Grades Removed: ${await Grade.countDocuments({ studentId: studentId })}`,
            adminMenu
        );
        
    } catch (error) {
        console.error('Error removing student:', error);
        await trackAdminActivity(ctx, 'remove_student_error', {
            studentId,
            error: error.message
        });
        
        await ctx.reply('❌ An error occurred while removing the student.', adminMenu);
    }
    
    delete ctx.session.studentToRemove;
    await ctx.scene.leave();
});

// Register the scene
stage.register(removeStudentScene);

// ... (rest of the code from demo.js remains unchanged)

// Create Delete Class Scene with Real-time Master Admin Notifications
const deleteClassScene = new Scenes.BaseScene('delete_class_scene');

deleteClassScene.enter(async (ctx) => {
    try {
        // Track admin activity
        await trackAdminActivity(ctx, 'delete_class_initiated');
        
        // Notify master admin
        await notifyMasterAdmin(ctx, 'delete_class_initiated', {
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id
        });
        
        // Get all available classes
        const availableClasses = await getUniqueClasses();
        
        if (availableClasses.length === 0) {
            ctx.reply('❌ No classes found to delete.', adminMenu);
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each class
        const classButtons = availableClasses.map(className => 
            [Markup.button.callback(
                className, 
                `delete_class_${className.replace(/\s+/g, '_')}`
            )]
        );
        
        // Add cancel button
        classButtons.push([Markup.button.callback('❌ Cancel', 'cancel_delete_class')]);
        
        ctx.reply('⚠️ *WARNING: This will permanently delete ALL data for the selected class!*\n\nSelect a class to delete:', 
            Markup.inlineKeyboard(classButtons));
    } catch (error) {
        console.error('Error retrieving classes for deletion:', error);
        await trackAdminActivity(ctx, 'delete_class_error', { error: error.message });
        await notifyMasterAdmin(ctx, 'delete_class_error', { 
            error: error.message,
            adminId: ctx.from.id
        });
        ctx.reply('❌ An error occurred while retrieving classes.', adminMenu);
        ctx.scene.leave();
    }
});

// Handle class selection for deletion
deleteClassScene.action(/^delete_class_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        // Track class selection
        
        
        // Store class name in session
        ctx.session.classToDelete = className;
        
        // Get statistics for confirmation
        const studentCount = await Student.countDocuments({ class: className });
        const teacherRelationsCount = await TeacherStudent.countDocuments({ className });
        
        ctx.replyWithHTML(
            `⚠️ *CONFIRM CLASS DELETION*\n\n` +
            `🏫 Class: *${className}*\n` +
            `👥 Students: ${studentCount}\n` +
            `📚 Teacher Relationships: ${teacherRelationsCount}\n\n` +
            `*This will permanently delete:*\n` +
            `• All students in this class\n` +
            `• All parent links for these students\n` +
            `• All teacher-student relationships for this class\n\n` +
            `*This action cannot be undone!*\n\n` +
            `Type CONFIRM to proceed or CANCEL to abort:`
        );
    } catch (error) {
        console.error('Error preparing class deletion:', error);
        await trackAdminActivity(ctx, 'delete_class_preparation_error', { 
            className, 
            error: error.message 
        });
        await notifyMasterAdmin(ctx, 'delete_class_preparation_error', { 
            className,
            error: error.message,
            adminId: ctx.from.id
        });
        ctx.reply('❌ An error occurred.', adminMenu);
        ctx.scene.leave();
    }
});

// Handle confirmation
deleteClassScene.on('text', async (ctx) => {
    const input = ctx.message.text.trim().toUpperCase();
    const className = ctx.session.classToDelete;
    
    if (!className) {
        ctx.reply('❌ No class selected. Please start over.', adminMenu);
        return ctx.scene.leave();
    }
    
    if (input === 'CANCEL') {
        await trackAdminActivity(ctx, 'delete_class_cancelled', { className });
        await notifyMasterAdmin(ctx, 'delete_class_cancelled', { 
            className,
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id
        });
        ctx.reply('❌ Class deletion cancelled.', adminMenu);
        delete ctx.session.classToDelete;
        return ctx.scene.leave();
    }
    
    if (input !== 'CONFIRM') {
        ctx.reply('❌ Please type CONFIRM to proceed or CANCEL to abort.');
        return;
    }
    
    try {
        // Track deletion start
        await trackAdminActivity(ctx, 'delete_class_started', { className });
        const masterAdminMsg = await notifyMasterAdmin(ctx, 'delete_class_started', { 
            className,
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id,
            status: 'processing'
        });
        
        // Get all students in the class
        const students = await Student.find({ class: className });
        const totalStudents = students.length;
        
        let deletedStudents = 0;
        let unlinkedParents = 0;
        let deletedTeacherRelations = 0;
        const studentDetails = [];
        const parentDetails = [];
        
        // Send initial progress message to admin
        const progressMsg = await ctx.reply(
            `⏳ Starting deletion process for ${className}\n` +
            `📊 Total students: ${totalStudents}\n` +
            `⏰ Estimated time: Calculating...`
        );
        
        const startTime = Date.now();
        let lastUpdateTime = startTime;
        let lastUpdateCount = 0;
        
        // Delete each student and handle parent unlinking
        for (let i = 0; i < totalStudents; i++) {
            const student = students[i];
            
            try {
                // Record student details for logging
                studentDetails.push({
                    studentId: student.studentId,
                    studentName: student.name
                });
                
                // Unlink parent if exists
                if (student.parentId) {
                    const parent = await getUserById(student.parentId);
                    if (parent) {
                        // Record parent details for logging
                        parentDetails.push({
                            parentId: parent.telegramId,
                            parentName: parent.name,
                            studentId: student.studentId
                        });
                        
                        parent.studentIds = parent.studentIds.filter(id => id !== student.studentId);
                        // If no more students, change role to user
                        if (parent.studentIds.length === 0) {
                            parent.role = 'user';
                            await trackAdminActivity(ctx, 'parent_demoted_to_user', {
                                parentId: parent.telegramId,
                                parentName: parent.name
                            });
                        }
                        await parent.save();
                        unlinkedParents++;
                        
                        await trackAdminActivity(ctx, 'parent_unlinked', {
                            studentId: student.studentId,
                            studentName: student.name,
                            parentId: parent.telegramId,
                            parentName: parent.name
                        });
                    }
                }
                
                // Delete student
                await Student.deleteOne({ studentId: student.studentId });
                deletedStudents++;
                
                await trackAdminActivity(ctx, 'student_deleted', {
                    studentId: student.studentId,
                    studentName: student.name,
                    className: className
                });
                
                // Update progress every 5 students or every 3 seconds
                const currentTime = Date.now();
                if (i % 5 === 0 || currentTime - lastUpdateTime > 3000) {
                    const elapsed = (currentTime - startTime) / 1000;
                    const itemsProcessed = i + 1;
                    const itemsPerSecond = itemsProcessed / elapsed;
                    const remainingItems = totalStudents - itemsProcessed;
                    const etaSeconds = itemsPerSecond > 0 ? Math.round(remainingItems / itemsPerSecond) : 0;
                    
                    // Update admin progress message
                    try {
                        await ctx.telegram.editMessageText(
                            progressMsg.chat.id,
                            progressMsg.message_id,
                            null,
                            `⏳ Deleting class: ${className}\n` +
                            `📊 Progress: ${itemsProcessed}/${totalStudents} students\n` +
                            `✅ Completed: ${Math.round((itemsProcessed / totalStudents) * 100)}%\n` +
                            `⏰ ETA: ${formatTime(etaSeconds)}\n` +
                            `🏎️ Speed: ${itemsPerSecond.toFixed(1)} students/sec`
                        );
                    } catch (editError) {
                        // Message might be too old to edit, continue silently
                    }
                    
                    // Update master admin every 10 students or 5 seconds
                    if (i % 10 === 0 || currentTime - lastUpdateTime > 5000) {
                        await notifyMasterAdmin(ctx, 'delete_class_progress', {
                            className,
                            progress: itemsProcessed,
                            total: totalStudents,
                            percentage: Math.round((itemsProcessed / totalStudents) * 100),
                            eta: formatTime(etaSeconds),
                            speed: itemsPerSecond.toFixed(1),
                            adminId: ctx.from.id,
                            messageId: masterAdminMsg?.message_id
                        }, masterAdminMsg?.message_id);
                        
                        lastUpdateTime = currentTime;
                        lastUpdateCount = itemsProcessed;
                    }
                }
                
            } catch (error) {
                console.error(`Error deleting student ${student.studentId}:`, error);
                await trackAdminActivity(ctx, 'student_deletion_error', {
                    studentId: student.studentId,
                    error: error.message
                });
            }
        }
        
        // Delete all teacher-student relationships for this class
        const teacherRelations = await TeacherStudent.find({ className });
        deletedTeacherRelations = teacherRelations.length;
        
        for (const relation of teacherRelations) {
            await trackAdminActivity(ctx, 'teacher_relation_deleted', {
                teacherId: relation.teacherId,
                teacherName: relation.teacherName,
                studentId: relation.studentId,
                studentName: relation.studentName,
                subject: relation.subject,
                className: relation.className
            });
        }
        
        await TeacherStudent.deleteMany({ className });
        
        // Track admin activity with comprehensive details
        await trackAdminActivity(ctx, 'delete_class_completed', {
            className: className,
            statistics: {
                deletedStudents: deletedStudents,
                unlinkedParents: unlinkedParents,
                deletedTeacherRelations: deletedTeacherRelations
            },
            studentDetails: studentDetails.slice(0, 10), // First 10 students for log
            parentDetails: parentDetails.slice(0, 10),   // First 10 parents for log
            totalStudents: students.length
        });
        
        // Create a detailed log file
        const logContent = generateClassDeletionLog(
            className,
            deletedStudents,
            unlinkedParents,
            deletedTeacherRelations,
            studentDetails,
            parentDetails,
            teacherRelations,
            ctx.from
        );
        
        // Send final update to admin
        await ctx.telegram.editMessageText(
            progressMsg.chat.id,
            progressMsg.message_id,
            null,
            `✅ Class deletion completed!\n` +
            `🏫 Class: ${className}\n` +
            `👥 Students deleted: ${deletedStudents}\n` +
            `👨‍👩‍👧‍👦 Parents unlinked: ${unlinkedParents}\n` +
            `📚 Teacher relationships removed: ${deletedTeacherRelations}\n` +
            `⏱️ Total time: ${formatTime((Date.now() - startTime) / 1000)}`
        );
        
        // Send the detailed log file
        const tempDir = './temp_logs';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        
        const fileName = `class_deletion_${className.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.log`;
        const filePath = path.join(tempDir, fileName);
        
        fs.writeFileSync(filePath, logContent);
        
        await ctx.replyWithDocument({
            source: filePath,
            filename: fileName,
            caption: `📋 Detailed deletion log for ${className}`
        });
        
        // Send completion notification to master admin
        await notifyMasterAdmin(ctx, 'delete_class_completed', {
            className,
            statistics: {
                deletedStudents,
                unlinkedParents,
                deletedTeacherRelations
            },
            totalTime: formatTime((Date.now() - startTime) / 1000),
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id,
            logFile: fileName
        });
        
        // Clean up log file after sending
        setTimeout(() => {
            if (fs.existsSync(filePath)) {
                try {
                    fs.unlinkSync(filePath);
                } catch (cleanupError) {
                    console.error('Error cleaning up log file:', cleanupError);
                }
            }
        }, 30000);
        
    } catch (error) {
        console.error('Error deleting class:', error);
        await trackAdminActivity(ctx, 'delete_class_error', {
            className,
            error: error.message,
            stack: error.stack
        });
        await notifyMasterAdmin(ctx, 'delete_class_error', {
            className,
            error: error.message,
            adminId: ctx.from.id
        });
        ctx.reply('❌ An error occurred while deleting the class.', adminMenu);
    }
    
    delete ctx.session.classToDelete;
    ctx.scene.leave();
});

// Handle cancellation from inline button
deleteClassScene.action('cancel_delete_class', async (ctx) => {
    await ctx.answerCbQuery();
    const className = ctx.session.classToDelete;
    await trackAdminActivity(ctx, 'delete_class_cancelled', { className });
    await notifyMasterAdmin(ctx, 'delete_class_cancelled', { 
        className,
        admin: ctx.from.first_name || 'Admin',
        adminId: ctx.from.id
    });
    ctx.reply('❌ Class deletion cancelled.', adminMenu);
    delete ctx.session.classToDelete;
    ctx.scene.leave();
});

// Helper function to format time
function formatTime(seconds) {
    if (seconds < 60) {
        return `${Math.round(seconds)} seconds`;
    } else if (seconds < 3600) {
        return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }
}


// Register the scene
stage.register(deleteClassScene);




// --- Master Admin Scenes ---

// View All Admins Scene
const viewAllAdminsScene = new Scenes.BaseScene('view_all_admins_scene');

viewAllAdminsScene.enter(async (ctx) => {
    try {
        const admins = await User.find({ role: 'admin' }).sort({ createdAt: 1 });
        
        if (admins.length === 0) {
            ctx.reply('❌ No admins found.', masterAdminMenu);
            return ctx.scene.leave();
        }

        let message = '👑 *All Administrators:*\n\n';
        
        admins.forEach((admin, index) => {
            const isMaster = admin.telegramId === process.env.MASTER_ADMIN_ID;
            message += `${index + 1}. ${admin.name} \n`;
            message += `   🆔 ID: ${admin.telegramId}\n`;
            message += `   👑 Role: ${isMaster ? 'Master Admin' : 'Admin'}\n`;
            message += `   📅 Registered: ${admin.createdAt.toLocaleDateString()}\n`;
            message += `   ⏰ Last Active: ${admin.lastActivity ? admin.lastActivity.toLocaleString() : 'Never'}\n`;
            message += `   📊 Activities: ${admin.activityLog?.length || 0} logged\n\n`;
        });

        ctx.replyWithHTML(message, masterAdminMenu);
        
    } catch (error) {
        console.error('Error viewing admins:', error);
        ctx.reply('❌ Error retrieving admin list.', masterAdminMenu);
    }
    ctx.scene.leave();
});

// Remove Admin Scene
const removeAdminScene = new Scenes.BaseScene('remove_admin_scene');

removeAdminScene.enter(async (ctx) => {
    try {
        const admins = await User.find({ 
            role: 'admin', 
            telegramId: { $ne: process.env.MASTER_ADMIN_ID } 
        }).sort({ name: 1 });

        if (admins.length === 0) {
            ctx.reply('❌ No removable admins found.', masterAdminMenu);
            return ctx.scene.leave();
        }

        const adminButtons = admins.map(admin => [
            Markup.button.callback(
                `${admin.name} (ID: ${admin.telegramId})`,
                `remove_admin_${admin.telegramId}`
            )
        ]);

        adminButtons.push([Markup.button.callback('❌ Cancel', 'cancel_remove_admin')]);

        ctx.reply('🗑️ Select an admin to remove:', Markup.inlineKeyboard(adminButtons));

    } catch (error) {
        console.error('Error in remove admin scene:', error);
        ctx.reply('❌ Error loading admins.', masterAdminMenu);
        ctx.scene.leave();
    }
});

removeAdminScene.action(/^remove_admin_(\d+)$/, async (ctx) => {
    const adminId = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const adminToRemove = await User.findOne({ telegramId: adminId, role: 'admin' });
        
        if (!adminToRemove) {
            ctx.reply('❌ Admin not found.', masterAdminMenu);
            return ctx.scene.leave();
        }

        if (adminId === process.env.MASTER_ADMIN_ID) {
            ctx.reply('❌ Cannot remove master admin.', masterAdminMenu);
            return ctx.scene.leave();
        }

        // Demote to user role
        adminToRemove.role = 'user';
        adminToRemove.adminId = null;
        await adminToRemove.save();

        await trackAdminActivity(ctx, 'admin_removed', { removedAdmin: adminId });
        
        ctx.replyWithHTML(
            `✅ *Admin removed successfully!*\n\n` +
            `👤 ${adminToRemove.name}\n` +
            `🆔 ${adminToRemove.telegramId}\n` +
            `⏰ ${new Date().toLocaleString()}`,
            masterAdminMenu
        );

        // Notify the removed admin
        try {
            await ctx.telegram.sendMessage(
                adminId,
                `ℹ️ Your administrator privileges have been removed by the master admin.`
            );
        } catch (notifyError) {
            console.error('Could not notify removed admin:', notifyError);
        }

    } catch (error) {
        console.error('Error removing admin:', error);
        ctx.reply('❌ Error removing admin.', masterAdminMenu);
    }
    ctx.scene.leave();
});

removeAdminScene.action('cancel_remove_admin', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Admin removal cancelled.', masterAdminMenu);
    ctx.scene.leave();
});

// Admin Activities Scene
// Alternative: Plain text version
const adminActivitiesScene = new Scenes.BaseScene('admin_activities_scene')

// Update the adminActivitiesScene to handle the full activity log button
adminActivitiesScene.action('view_full_activities', async (ctx) => {
    await ctx.answerCbQuery();
    
    try {
        const admins = await User.find({ role: 'admin' }).sort({ name: 1 });
        
        // Collect all activities from all admins
        const allActivities = [];
        admins.forEach(admin => {
            if (admin.activityLog && admin.activityLog.length > 0) {
                admin.activityLog.forEach(activity => {
                    allActivities.push({
                        admin: admin.name,
                        adminId: admin.telegramId,
                        timestamp: activity.timestamp,
                        action: activity.action,
                        details: activity.details
                    });
                });
            }
        });

        // Sort by timestamp (newest first)
        allActivities.sort((a, b) => b.timestamp - a.timestamp);
        
        if (allActivities.length === 0) {
            await ctx.reply('❌ No activities found in the log.');
            return;
        }

        // Create comprehensive log file content
        let logContent = `SCHOOL SYSTEM BOT - FULL ADMIN ACTIVITY LOG\n`;
        logContent += `Generated: ${new Date().toLocaleString()}\n`;
        logContent += `Total Activities: ${allActivities.length}\n`;
        logContent += '='.repeat(80) + '\n\n';
        
        // Group activities by admin for better organization
        const activitiesByAdmin = {};
        allActivities.forEach(activity => {
            if (!activitiesByAdmin[activity.admin]) {
                activitiesByAdmin[activity.admin] = [];
            }
            activitiesByAdmin[activity.admin].push(activity);
        });

        // Add summary section
        logContent += 'SUMMARY:\n';
        logContent += '='.repeat(80) + '\n';
        Object.keys(activitiesByAdmin).forEach(adminName => {
            logContent += `• ${adminName}: ${activitiesByAdmin[adminName].length} activities\n`;
        });
        logContent += '\n';

        // Add detailed activities by admin
        Object.keys(activitiesByAdmin).forEach(adminName => {
            const adminActivities = activitiesByAdmin[adminName];
            
            logContent += `ADMIN: ${adminName} (ID: ${adminActivities[0].adminId})\n`;
            logContent += '-'.repeat(80) + '\n';
            
            adminActivities.forEach((activity, index) => {
                logContent += `Activity ${index + 1}:\n`;
                logContent += `  Time: ${activity.timestamp.toLocaleString()}\n`;
                logContent += `  Action: ${activity.action}\n`;
                
                if (activity.details) {
                    if (activity.details.messageText) {
                        logContent += `  Message: ${activity.details.messageText}\n`;
                    }
                    if (activity.details.command) {
                        logContent += `  Command: ${activity.details.command}\n`;
                    }
                    if (activity.details.removedAdmin) {
                        logContent += `  Removed Admin: ${activity.details.removedAdmin}\n`;
                    }
                    if (activity.details.promotedUser) {
                        logContent += `  Promoted User: ${activity.details.promotedUser}\n`;
                    }
                    if (activity.details.chatType) {
                        logContent += `  Chat Type: ${activity.details.chatType}\n`;
                    }
                    if (activity.details?.uploadedFile) {
                        logContent += `  📤 Uploaded: ${activity.details.uploadedFile.name} (Class: ${activity.details.uploadedFile.class})\n`;
                    }
                    if (activity.details?.removedFileId) {
                        logContent += `  🗑️ Removed Uploaded File ID: ${activity.details.removedFileId}\n`;
                    }
                    if (activity.details?.model) {
                        logContent += `  ⚙️ DB Change: ${activity.details.model}.${activity.details.operation} (Target: ${activity.details.targetId})\n`;
                    }

                }
                
                logContent += '\n';
            });
            
            logContent += '\n';
        });

        // Add statistics section
        logContent += 'STATISTICS:\n';
        logContent += '='.repeat(80) + '\n';
        
        // Count actions by type
        const actionCounts = {};
        allActivities.forEach(activity => {
            actionCounts[activity.action] = (actionCounts[activity.action] || 0) + 1;
        });
        
        logContent += 'Actions by Type:\n';
        Object.keys(actionCounts).sort().forEach(action => {
            logContent += `  ${action}: ${actionCounts[action]}\n`;
        });
        
        logContent += '\nActivity Timeline:\n';
        const firstActivity = allActivities[allActivities.length - 1];
        const lastActivity = allActivities[0];
        logContent += `  First Activity: ${firstActivity.timestamp.toLocaleString()}\n`;
        logContent += `  Last Activity: ${lastActivity.timestamp.toLocaleString()}\n`;
        logContent += `  Time Span: ${Math.round((lastActivity.timestamp - firstActivity.timestamp) / (1000 * 60 * 60 * 24))} days\n`;

        // Create temporary file
        const tempDir = './temp_logs';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        
        const fileName = `admin_activities_full_${new Date().toISOString().split('T')[0]}.log`;
        const filePath = path.join(tempDir, fileName);
        
        fs.writeFileSync(filePath, logContent);

        // Send the log file
        await ctx.replyWithDocument({
            source: filePath,
            filename: fileName,
            caption: `📋 Full Admin Activity Log\n📊 ${allActivities.length} activities total`
        });

        // Clean up
        setTimeout(() => {
            if (fs.existsSync(filePath)) {
                try {
                    fs.unlinkSync(filePath);
                } catch (cleanupError) {
                    console.error('Error cleaning up log file:', cleanupError);
                }
            }
        }, 30000); // Clean up after 30 seconds

    } catch (error) {
        console.error('Error generating full activity log:', error);
        await ctx.reply('❌ Error generating activity log. Please try again.');
    }
});

// Add back button handler
adminActivitiesScene.action('back_to_master_menu', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('Returning to master admin menu...', masterAdminMenu);
    ctx.scene.leave();
});

const trackAdminActivity = async (ctx, action, details = {}) => {
    try {
        if (ctx.from && ctx.from.id) {
            const user = await User.findOne({ telegramId: ctx.from.id.toString() });

            // ✅ Only log if user is admin or master admin
            if (user && (user.role === 'admin' || user.masterAdmin)) {
                user.lastActivity = new Date();

                const activityDetails = {
                    ...details,
                    messageText: ctx.message?.text?.substring(0, 200),
                    chatType: ctx.chat?.type,
                    chatId: ctx.chat?.id,
                    messageId: ctx.message?.message_id
                };

                Object.keys(activityDetails).forEach(k => {
                    if (activityDetails[k] === undefined) delete activityDetails[k];
                });

                user.activityLog.push({
                    action,
                    timestamp: new Date(),
                    details: activityDetails
                });

                if (user.activityLog.length > 500) {
                    user.activityLog = user.activityLog.slice(-500);
                }

                await user.save();

                // Notify master admin on critical DB actions
                const criticalActions = [
                    'add_admin', 'remove_admin', 'admin_promoted', 'admin_demoted',
                    'ban_user', 'unban_user',
                    'approve_request', 'deny_request',
                    'upload_document', 'remove_uploaded_list',
                    'modify_database'
                ];

                if (criticalActions.includes(action)) {
                    await notifyMasterAdmin(ctx, action, details);
                }
            }
        }
    } catch (err) {
        console.error('Error tracking admin activity:', err);
    }
};

// Add a function to periodically clean up old log files
const setupLogCleanup = () => {
    // Clean up temp logs directory every hour
    setInterval(async () => {
        try {
            const tempDir = './temp_logs';
            if (fs.existsSync(tempDir)) {
                const files = fs.readdirSync(tempDir);
                const now = Date.now();
                
                files.forEach(file => {
                    const filePath = path.join(tempDir, file);
                    const stats = fs.statSync(filePath);
                    
                    // Delete files older than 1 hour
                    if (now - stats.mtimeMs > 60 * 60 * 1000) {
                        fs.unlinkSync(filePath);
                        console.log(`Cleaned up old log file: ${file}`);
                    }
                });
            }
        } catch (error) {
            console.error('Error in log cleanup:', error);
        }
    }, 60 * 60 * 1000); // Run every hour
};

// Call this during bot startup
setupLogCleanup();

adminActivitiesScene.enter(async (ctx) => {
    try {
        const admins = await User.find({ role: 'admin' }).sort({ lastActivity: -1 });
        
        let message = '📊 RECENT ADMIN ACTIVITIES\n\n';
        
        // Get recent activities from all admins
        const allActivities = [];
        admins.forEach(admin => {
            if (admin.activityLog && admin.activityLog.length > 0) {
                admin.activityLog.forEach(activity => {
                    allActivities.push({
                        admin: admin.name,
                        timestamp: activity.timestamp,
                        action: activity.action,
                        details: activity.details
                    });
                });
            }
        });

        // Sort by timestamp (newest first)
        allActivities.sort((a, b) => b.timestamp - a.timestamp);
        
        // Show top 10 recent activities
        const recentActivities = allActivities.slice(0, 10);
        
        if (recentActivities.length === 0) {
            message += 'No recent activities found.';
        } else {
            recentActivities.forEach((activity, index) => {
                message += `${index + 1}. ${activity.admin} - ${activity.action}\n`;
                message += `   ⏰ ${activity.timestamp.toLocaleString()}\n`;
                if (activity.details?.messageText) {
                    message += `   💬 ${activity.details.messageText.substring(0, 50)}...\n`;
                }
                message += '\n';
            });
        }

        ctx.reply(message, Markup.inlineKeyboard([
            [Markup.button.callback('📋 Full Activity Log', 'view_full_activities')],
            [Markup.button.callback('⬅️ Back', 'back_to_master_menu')]
        ]));

    } catch (error) {
        console.error('Error viewing activities:', error);
        ctx.reply('❌ Error retrieving activities.', masterAdminMenu);
        ctx.scene.leave();
    }
});
// Promote to Admin Scene
const promoteToAdminScene = new Scenes.BaseScene('promote_to_admin_scene');

promoteToAdminScene.enter((ctx) => {
    ctx.reply('👑 Enter the Telegram ID of the user to promote to admin:');
});

promoteToAdminScene.on('text', async (ctx) => {
    const telegramId = ctx.message.text.trim();
    
    if (!isValidTelegramId(telegramId)) {
        ctx.reply('❌ Invalid Telegram ID format.');
        return;
    }

    try {
        const user = await User.findOne({ telegramId });
        
        if (!user) {
            ctx.reply('❌ User not found. They must have interacted with the bot first.');
            return ctx.scene.leave();
        }

        if (user.role === 'admin') {
            ctx.reply('❌ User is already an admin.');
            return ctx.scene.leave();
        }

        // Promote to admin
        user.role = 'admin';
        user.adminId = await generateUniqueAdminId();
        await user.save();

        await trackAdminActivity(ctx, 'admin_promoted', { promotedUser: telegramId });
        
        ctx.replyWithHTML(
            `✅ *User promoted to admin!*\n\n` +
            `👤 ${user.name}\n` +
            `🆔 ${user.telegramId}\n` +
            `🎭 New Role: Admin\n` +
            `⏰ ${new Date().toLocaleString()}`,
            masterAdminMenu
        );

        // Notify the new admin
        try {
            await ctx.telegram.sendMessage(
                telegramId,
                `🎉 You have been promoted to administrator by the master admin!\n\n` +
                `You now have access to the admin panel with special privileges.`
            );
        } catch (notifyError) {
            console.error('Could not notify new admin:', notifyError);
        }

    } catch (error) {
        console.error('Error promoting user:', error);
        ctx.reply('❌ Error promoting user to admin.', masterAdminMenu);
    }
    ctx.scene.leave();
});

// Register all master admin scenes
stage.register(viewAllAdminsScene);
stage.register(removeAdminScene);
stage.register(adminActivitiesScene);
stage.register(promoteToAdminScene);

const parentUnlinkScene = new Scenes.BaseScene('parent_unlink_scene');

// Step 1: Enter → list linked students
parentUnlinkScene.enter(async (ctx) => {
    try {
        const parent = await User.findOne({ telegramId: ctx.from.id, role: 'parent' });
        if (!parent) {
            ctx.reply('❌ You are not registered as a parent.');
            return ctx.scene.leave();
        }

        const students = await Student.find({ parentId: ctx.from.id });
        if (!students.length) {
            ctx.reply('❌ You have no students linked.');
            return ctx.scene.leave();
        }

        const buttons = students.map(s => [
            Markup.button.callback(`${s.name} (${s.studentId})`, `unlink_select_${s.studentId}`)
        ]);

        ctx.reply('👨‍🎓 Select a student to unlink:', Markup.inlineKeyboard(buttons));
    } catch (err) {
        console.error('Error in unlink scene:', err);
        ctx.reply('❌ Failed to load students.');
        ctx.scene.leave();
    }
});

// Step 2: Parent selects student
parentUnlinkScene.action(/unlink_select_(.+)/, async (ctx) => {
    await ctx.answerCbQuery();
    const studentId = ctx.match[1];

    const student = await Student.findOne({ studentId });
    if (!student) {
        ctx.reply('❌ Student not found.');
        return;
    }

    ctx.session.unlinkStudentId = studentId;

    ctx.reply(
        `⚠️ Are you sure you want to unlink *${student.name}* (${student.studentId})?`,
        {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: [
                    [
                        { text: '✅ Yes, unlink', callback_data: 'unlink_confirm' },
                        { text: '❌ Cancel', callback_data: 'unlink_cancel' }
                    ]
                ]
            }
        }
    );
});

// Step 3: Cancel
parentUnlinkScene.action('unlink_cancel', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Unlink cancelled.', parentMenu);
    ctx.scene.leave();
});

// Step 4: Confirm → send request to admins
parentUnlinkScene.action('unlink_confirm', async (ctx) => {
    await ctx.answerCbQuery();

    const studentId = ctx.session.unlinkStudentId;
    if (!studentId) {
        ctx.reply('❌ No student selected.');
        return ctx.scene.leave();
    }

    const student = await Student.findOne({ studentId });
    if (!student) {
        ctx.reply('❌ Student not found.');
        return ctx.scene.leave();
    }

    const parent = await User.findOne({ telegramId: ctx.from.id });

    // Notify admins
    const admins = await User.find({ role: 'admin' });
    for (const admin of admins) {
        await ctx.telegram.sendMessage(
            admin.telegramId,
            `🔗 *Unlink Request*\n\n` +
            `👤 Parent: ${parent.name} (${parent.telegramId})\n` +
            `👨‍🎓 Student: ${student.name} (${student.studentId})\n\n` +
            `Do you approve this unlinking?`,
            {
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [
                            { text: '✅ Confirm', callback_data: `admin_unlink_yes_${parent.telegramId}_${studentId}` },
                            { text: '❌ Deny', callback_data: `admin_unlink_no_${parent.telegramId}_${studentId}` }
                        ]
                    ]
                }
            }
        );
    }

    ctx.reply('📨 Your request has been sent to administrators for approval.');
    ctx.scene.leave();
});

// ✅ Register the scene like all the others
stage.register(parentUnlinkScene);

// --- Teacher Forgot Password Scene ---
const teacherForgotPasswordScene = new Scenes.BaseScene('teacher_forgot_password_scene');

teacherForgotPasswordScene.enter((ctx) => {
    ctx.reply(
        '❓ Forgot Password\n\n' +
        'Do you want to request an OTP for password reset?\n\n' +
        'Type YES to continue or NO to cancel.'
    );
});

teacherForgotPasswordScene.on('text', async (ctx) => {
    const text = ctx.message.text.trim().toUpperCase();

    // Stage 2: waiting for OTP
    if (ctx.session.awaitingResetOTP) {
        if (!/^\d{6}$/.test(text)) {
            return ctx.reply('❌ Please enter a valid 6-digit OTP.');
        }

        const otpRecord = await OTP.findOne({ telegramId: ctx.from.id });

        if (!otpRecord || isOTPExpired(otpRecord.expiresAt)) {
            ctx.reply('❌ OTP expired or not found. Please try again.');
            await OTP.deleteOne({ telegramId: ctx.from.id });
            delete ctx.session.awaitingResetOTP;
            return ctx.scene.leave();
        }

        if (text !== otpRecord.otp) {
            ctx.reply('❌ Incorrect OTP. Try again.');
            return;
        }

        // ✅ OTP correct → reset password
        try {
            const user = await User.findOne({ telegramId: ctx.from.id, role: 'teacher' });
if (!user) {
    ctx.reply('❌ You are not registered as a teacher.');
    return ctx.scene.leave();
}

// Find teacher by name (or any other strong link you keep consistent)
const teacher = await Teacher.findOne({ name: user.name });
if (!teacher) {
    ctx.reply('❌ Teacher profile not found.');
    return ctx.scene.leave();
}
            const newPassword = generatePassword();
            const hashedPassword = hashPassword(newPassword);

            await TeacherLogin.updateOne(
                { teacherId: teacher.teacherId },
                { password: hashedPassword }
            );

            await OTP.deleteOne({ telegramId: ctx.from.id });
            delete ctx.session.awaitingResetOTP;

            ctx.replyWithHTML(
                `✅ *Password Reset Successful!*\n\n` +
                `👤 Name: ${teacher.name}\n` +
                `🆔 Teacher ID: ${teacher.teacherId}\n` +
                `🔐 New Password: ${newPassword}\n\n` +
                `_Please save your new password securely._`,
                postLogoutMenu
            );
        } catch (err) {
            console.error('Error resetting password:', err);
            ctx.reply('❌ Failed to reset password.');
        } finally {
            ctx.scene.leave();
        }

        return;
    }

    // Stage 1: Confirmation step
    if (text === 'NO' || text === 'CANCEL') {
        ctx.reply('❌ Password reset cancelled.', postLogoutMenu);
        return ctx.scene.leave();
    }

    if (text === 'YES') {
        try {
       const user = await User.findOne({ telegramId: ctx.from.id, role: 'teacher' });
if (!user) {
    ctx.reply('❌ You are not registered as a teacher.');
    return ctx.scene.leave();
}

// Find teacher by name (or any other strong link you keep consistent)
const teacher = await Teacher.findOne({ name: user.name });
if (!teacher) {
    ctx.reply('❌ Teacher profile not found.');
    return ctx.scene.leave();
}

            // Generate OTP
            const otp = generateOTP();
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

            await OTP.deleteOne({ telegramId: ctx.from.id }); // clear old
            await new OTP({
                telegramId: ctx.from.id,
                otp,
                expiresAt,
                code: otp
            }).save();

            // Notify admins
            const admins = await getAdmins();
            for (const admin of admins) {
                try {
                    await ctx.telegram.sendMessage(
                        admin.telegramId,
                        `🔑 *Password Reset Request:*\n\n` +
                        `👤 Teacher: ${teacher.name}\n` +
                        `🆔 Teacher ID: ${teacher.teacherId}\n` +
                        `📱 Telegram ID: ${ctx.from.id}\n\n` +
                        `🔢 *OTP Code:* ${otp}\n` +
                        `⏰ Expires: ${expiresAt.toLocaleTimeString()}`,
                        { parse_mode: "HTML" }
                    );
                } catch (err) {
                    console.error(`Failed to notify admin ${admin.telegramId}:`, err);
                }
            }

            ctx.reply('📧 OTP has been sent to administrators. Please enter the 6-digit OTP code:');
            ctx.session.awaitingResetOTP = true;

        } catch (error) {
            console.error('Error requesting password reset:', error);
            ctx.reply('❌ Failed to request password reset.');
            ctx.scene.leave();
        }

        return;
    }

    // Fallback if invalid input at first stage
    return ctx.reply('❌ Please type YES to continue or NO to cancel.');
});
// Handle OTP input
teacherForgotPasswordScene.on('text', async (ctx) => {
    if (!ctx.session.awaitingResetOTP) return;

    const input = ctx.message.text.trim();

    if (!/^\d{6}$/.test(input)) {
        return ctx.reply('❌ Please enter a valid 6-digit OTP.');
    }

    const otpRecord = await OTP.findOne({ telegramId: ctx.from.id });

    if (!otpRecord || isOTPExpired(otpRecord.expiresAt)) {
        ctx.reply('❌ OTP expired or not found. Please try again.');
        await OTP.deleteOne({ telegramId: ctx.from.id });
        return ctx.scene.leave();
    }

    if (input !== otpRecord.otp) {
        ctx.reply('❌ Incorrect OTP. Try again.');
        return;
    }

    // OTP correct → reset password
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher) {
            ctx.reply('❌ Teacher not found.');
            return ctx.scene.leave();
        }

        const newPassword = generatePassword();
        const hashedPassword = hashPassword(newPassword);

        await TeacherLogin.updateOne(
            { teacherId: teacher.teacherId },
            { password: hashedPassword }
        );

        await OTP.deleteOne({ telegramId: ctx.from.id });

        ctx.replyWithHTML(
            `✅ *Password Reset Successful!*\n\n` +
            `👤 Name: ${teacher.name}\n` +
            `🆔 Teacher ID: ${teacher.teacherId}\n` +
            `🔐 New Password: ${newPassword}\n\n` +
            `_Please save your new password securely._`,
            postLogoutMenu
        );

    } catch (err) {
        console.error('Error resetting password:', err);
        ctx.reply('❌ Failed to reset password.');
    } finally {
        delete ctx.session.awaitingResetOTP;
        ctx.scene.leave();
    }
});

stage.register(teacherForgotPasswordScene);

const requestStudentsListScene = new Scenes.BaseScene('request_students_list_scene');

requestStudentsListScene.enter(async (ctx) => {
  try {
    const classes = await getUniqueClasses();
    if (classes.length === 0) {
      ctx.reply('❌ No classes available.');
      return ctx.scene.leave();
    }
    const buttons = classes.map(cls => [Markup.button.callback(cls, `select_class_${cls.replace(/ /g, '_')}`)]);
    buttons.push([Markup.button.callback('❌ Cancel', 'cancel_request_students_list')]);
    await ctx.reply('📚 Select the class for which you want to request the student list:', Markup.inlineKeyboard(buttons));
  } catch (error) {
    console.error('Error fetching classes:', error);
    ctx.reply('❌ Could not fetch classes. Try again later.');
    ctx.scene.leave();
  }
});

requestStudentsListScene.action(/^select_class_(.+)$/, async (ctx) => {
  const className = ctx.match[1].replace(/_/g, ' ');
  ctx.session.requestClass = className;

  const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
  const currentSubjects = teacher.subjects || [];
  if (currentSubjects.length === 0) {
    await ctx.reply('❌ You have no subjects assigned.');
    return ctx.scene.leave();
  }

  const subjectButtons = currentSubjects.map(subject => [Markup.button.callback(subject, `select_subject_${subject.replace(/ /g, '_')}`)]);
  subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_request_students_list')]);

  await ctx.reply(`📖 You selected class "${className}". Now select the subject:`, Markup.inlineKeyboard(subjectButtons));
});

requestStudentsListScene.action(/^select_subject_(.+)$/, async (ctx) => {
  const subject = ctx.match[1].replace(/_/g, ' ');
  ctx.session.requestSubject = subject;

  await ctx.reply(`✅ Confirm your request:\n\nClass: *${ctx.session.requestClass}*\nSubject: *${subject}*\n\nType CONFIRM to proceed or CANCEL to abort.`, { parse_mode: "HTML" });
  ctx.session.awaitingConfirmation = true;
});

requestStudentsListScene.on('text', async (ctx) => {
  if (!ctx.session.awaitingConfirmation) {
    return ctx.reply('❌ Please select a class and subject first.');
  }

  const input = ctx.message.text.trim().toUpperCase();
  if (input === 'CANCEL' || input === '❌ CANCEL') {
    await ctx.reply('❌ Request cancelled.', teacherMenu);
    return ctx.scene.leave();
  }
  if (input !== 'CONFIRM') {
    return ctx.reply('❌ Please type CONFIRM to submit or CANCEL to abort.');
  }

  try {
    // Save request in DB
    
    const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
    if (!teacher) {
      ctx.reply('❌ Teacher profile not found.');
      return ctx.scene.leave();
    }

    // Create new request
    const newRequest = new StudentListRequest({
      teacherId: teacher.teacherId,
      teacherTelegramId: ctx.from.id,
      className: ctx.session.requestClass,
      subject: ctx.session.requestSubject,
    });

    await newRequest.save();

    // Notify admins about new request (admins code assumed available)
    const admins = await User.find({ role: 'admin' });
    for (const admin of admins) {
      try {
        
        await ctx.telegram.sendMessage(
  admin.telegramId,
  `📋 *Student List Request*\n\n` +
  `Teacher: ${teacher.name} (${teacher.teacherId})\n` +
  `Class: ${ctx.session.requestClass}\n` +
  `Subject: ${ctx.session.requestSubject}\n` +
  `Use the buttons below to Approve or Deny.`,
  {




    parse_mode: "HTML",
    ...Markup.inlineKeyboard([
      Markup.button.callback('✅ Approve', `approve_request_${newRequest._id}`),
      Markup.button.callback('❌ Deny', `deny_request_${newRequest._id}`)
    ])
  }
);

      } catch (e) {
        console.error(`Failed to notify admin ${admin.telegramId}:`, e);
      }
    }

    ctx.reply('✅ Your request has been sent for admin approval.', teacherMenu);
    ctx.scene.leave();

  } catch (err) {
    console.error('Error saving request:', err);
    ctx.reply('❌ Failed to submit request.');
    ctx.scene.leave();
  }
});

requestStudentsListScene.action('cancel_request_students_list', async (ctx) => {
  await ctx.answerCbQuery();
  await ctx.reply('❌ Request cancelled.', teacherMenu);
  ctx.scene.leave();
});
stage.register(requestStudentsListScene);

// Teacher Registration Start Scene - ;

// Teacher Registration Start Scene - WITH SCHOOL CODE VERIFICATION
const teacherRegisterStartScene = new Scenes.BaseScene('teacher_register_start_scene');

teacherRegisterStartScene.enter(async (ctx) => {
    try {
        // Enhanced check: Verify user is not already a teacher
        const existingTeacher = await Teacher.findOne({ teacherId: ctx.from.id });
        if (existingTeacher) {
            const message = `✅ You are already registered as a teacher!\n\n` +
                           `👤 Name: ${existingTeacher.name}\n` +
                           `🆔 Teacher ID: ${existingTeacher.teacherId}\n\n` +
                           `Use the "🔐 Teacher Login" option to access your account.`;
            ctx.reply(message, teacherMenu);
            return ctx.scene.leave();
        }
        
        // Check if user is already a teacher in user collection
        const user = await getUserById(ctx.from.id);
        if (user && user.role === 'teacher') {
            ctx.reply('✅ You are already registered as a teacher! Use the "🔐 Teacher Login" option.', postLogoutMenu);
            return ctx.scene.leave();
        }

        // Check if already has pending registration
        const existingOTP = await OTP.findOne({ telegramId: ctx.from.id });
        if (existingOTP && !isOTPExpired(existingOTP.expiresAt) && !existingOTP.verified) {
            ctx.reply('📧 You already have a pending registration. Please check your messages for the OTP.');
            return ctx.scene.leave();
        }

        // Ask for school code first
        ctx.reply(
            '🏫 Teacher Registration\n\n' +
            'Please enter your school verification code to continue:',
            Markup.keyboard([['❌ Cancel Registration']]).resize()
        );
        ctx.session.awaitingSchoolCode = true;

    } catch (error) {
        console.error('Error in teacher registration start:', error);
        ctx.reply('❌ An error occurred while starting registration. Please try again.');
        ctx.scene.leave();
    }
});

teacherRegisterStartScene.on('text', async (ctx) => {
    const text = ctx.message.text.trim();

    if (text === '❌ Cancel Registration') {
        await OTP.deleteOne({ telegramId: ctx.from.id });
        ctx.reply('❌ Registration cancelled.', Markup.removeKeyboard());
        return ctx.scene.leave();
    }

    // Stage 1: School code verification
    if (ctx.session.awaitingSchoolCode) {
        const schoolCode = process.env.SCHOOL_CODE;
        
        if (!schoolCode) {
            ctx.reply('❌ School verification system is not configured. Please contact administration.');
            return ctx.scene.leave();
        }

        if (text !== schoolCode) {
            ctx.reply('❌ Invalid school code. Please try again or contact your school administration.');
            return;
        }

        // School code is correct - proceed to OTP generation
        ctx.session.awaitingSchoolCode = false;
        
        try {
            // Generate and send OTP to admins
            const otp = generateOTP();
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiration

            // Delete any existing OTP
            await OTP.deleteOne({ telegramId: ctx.from.id });

            // Save new OTP
            const newOTP = new OTP({
                telegramId: ctx.from.id,
                otp: otp,
                expiresAt: expiresAt,
                code: otp // Set code to the same value as otp to avoid null
            });
            await newOTP.save();

            // Notify all admins
            const admins = await getAdmins();
            let notifiedAdmins = 0;

            for (const admin of admins) {
                try {
                    await ctx.telegram.sendMessage(
                        admin.telegramId,
                        `🔐 *New Teacher Registration Request:*\n\n` +
                        `👤 Telegram User: ${ctx.from.first_name || 'Unknown'} ${ctx.from.last_name || ''}\n` +
                        `📱 Username: @${ctx.from.username || 'N/A'}\n` +
                        `🆔 Telegram ID: ${ctx.from.id}\n` +
                        `✅ School Code Verified: Yes\n\n` +
                        `🔢 *OTP Code:* ${otp}\n` +
                        `⏰ Expires: ${expiresAt.toLocaleTimeString()}`,
                        { parse_mode: "HTML" }
                    );
                    notifiedAdmins++;
                } catch (error) {
                    console.error(`Failed to notify admin ${admin.telegramId}:`, error);
                }
            }

            if (notifiedAdmins > 0) {
                ctx.reply(
                    '✅ School code verified!\n\n' +
                    '📧 A verification code has been sent to administrators.\n\n' +
                    'Please wait for an admin to provide you with the 6-digit verification code, then enter it below:',
                    Markup.keyboard([['❌ Cancel Registration']]).resize()
                );
            } else {
                ctx.reply('❌ No administrators are available to process your registration. Please try again later.');
                await OTP.deleteOne({ telegramId: ctx.from.id });
                ctx.scene.leave();
            }
        } catch (error) {
            console.error('Error generating OTP:', error);
            ctx.reply('❌ An error occurred during registration. Please try again.');
            ctx.scene.leave();
        }
        return;
    }

    // Stage 2: OTP verification (existing code remains the same)
    if (!/^\d{6}$/.test(text)) {
        ctx.reply('❌ Please enter a valid 6-digit verification code.');
        return;
    }

    const otpRecord = await OTP.findOne({ telegramId: ctx.from.id });
    
    if (!otpRecord) {
        ctx.reply('❌ No registration request found. Please start over.');
        return ctx.scene.leave();
    }

    if (isOTPExpired(otpRecord.expiresAt)) {
        ctx.reply('❌ Verification code has expired. Please start registration again.');
        await OTP.deleteOne({ telegramId: ctx.from.id });
        return ctx.scene.leave();
    }

    if (otpRecord.attempts >= 3) {
        ctx.reply('❌ Too many failed attempts. Please start registration again.');
        await OTP.deleteOne({ telegramId: ctx.from.id });
        return ctx.scene.leave();
    }

    if (text !== otpRecord.otp) {
        otpRecord.attempts += 1;
        await otpRecord.save();
        
        const remainingAttempts = 3 - otpRecord.attempts;
        ctx.reply(`❌ Invalid verification code. ${remainingAttempts} attempt(s) remaining.`);
        return;
    }

    // OTP is correct
    otpRecord.verified = true;
    await otpRecord.save();

    // FINAL CHECK: Ensure no duplicate teacher exists before proceeding
    const existingTeacher = await Teacher.findOne({ telegramId: ctx.from.id });
    if (existingTeacher) {
        const message = `✅ You are already registered as a teacher!\n\n` +
                       `👤 Name: ${existingTeacher.name}\n` +
                       `🆔 Teacher ID: ${existingTeacher.teacherId}\n\n` +
                       `Use the "🔐 Teacher Login" option to access your account.`;
        ctx.reply(message, teacherMenu);
        
        // Clean up OTP
        await OTP.deleteOne({ telegramId: ctx.from.id });
        
        return ctx.scene.leave();
    }
 
    ctx.reply('✅ Verification successful! Please enter your full name:');
    ctx.scene.enter('teacher_register_name_scene');
});

// Add action handler for cancellation
teacherRegisterStartScene.action('cancel_registration', async (ctx) => {
    await ctx.answerCbQuery();
    await OTP.deleteOne({ telegramId: ctx.from.id });
    delete ctx.session.awaitingSchoolCode;
    ctx.reply('❌ Registration cancelled.', Markup.removeKeyboard());
    ctx.scene.leave();
});

// Register the scene
stage.register(teacherRegisterStartScene);
// Teacher Register Name Scene - FIXED VERSION with duplicate protection
const teacherRegisterNameScene = new Scenes.BaseScene('teacher_register_name_scene');

teacherRegisterNameScene.enter(async (ctx) => {
    // Check if user is already a teacher before proceeding
    const existingTeacher = await Teacher.findOne({ telegramId: ctx.from.id });
    if (existingTeacher) {
        ctx.reply('✅ You are already registered as a teacher!', teacherMenu);
        return ctx.scene.leave();
    }
    
    // Check if user already has teacher role
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        ctx.reply('✅ You are already registered as a teacher!', teacherMenu);
        return ctx.scene.leave();
    }
    
    ctx.reply('👤 Please enter your full name:');
});
teacherRegisterNameScene.on('text', async (ctx) => {
    const text = ctx.message.text.trim();
    
    // Handle confirmation/cancellation if we're in that state
    if (ctx.session.waitingForConfirmation) {
        if (text === 'CONFIRM') {
            const name = ctx.session.teacherName;
            const password = ctx.session.tempPassword;
            
            try {
                // FINAL CHECK: Ensure no duplicate teacher exists
                const existingTeacher = await Teacher.findOne({ telegramId: ctx.from.id });
                if (existingTeacher) {
                    ctx.reply('✅ You are already registered as a teacher!', teacherMenu);
                    
                    // Clean up OTP
                    await OTP.deleteOne({ telegramId: ctx.from.id });
                    
                    // Clear session
                    delete ctx.session.teacherName;
                    delete ctx.session.tempPassword;
                    delete ctx.session.waitingForConfirmation;
                    
                    return ctx.scene.leave();
                }
                
                // Generate unique teacher ID
                const teacherId = await generateUniqueTeacherId();
                
                // Create teacher record
                const newTeacher = new Teacher({
                    teacherId: teacherId,
                    name: name,
                    telegramId: ctx.from.id,
                    subjects: [],
                    pendingSubjects: []
                });
                await newTeacher.save();
                
                // Create login record with hashed password
                const hashedPassword = hashPassword(password);
                const teacherLogin = new TeacherLogin({
                    teacherId: teacherId,
                    password: hashedPassword
                });
                await teacherLogin.save();
                
                // Create/update user record
                let user = await getUserById(ctx.from.id);
                if (user) {
                    user.role = 'teacher';
                    user.name = name;
                    await user.save();
                } else {
                    user = new User({
                        telegramId: ctx.from.id,
                        username: ctx.from.username || '',
                        name: name,
                        role: 'teacher'
                    });
                    await user.save();
                }
                
                // Clean up OTP
                await OTP.deleteOne({ telegramId: ctx.from.id });
                
                // Clear session
                delete ctx.session.teacherName;
                delete ctx.session.tempPassword;
                delete ctx.session.waitingForConfirmation;
                
                ctx.replyWithHTML(
                    `✅ *Registration Successful!*\n\n` +
                    `👤 Name: ${name}\n` +
                    `🆔 Teacher ID: ${teacherId}\n` +
                    `🔐 Password: ${password}\n\n` +
                    `_Please save your Teacher ID and Password in a secure place._`,
                    await getLoginMenu(ctx.from.id)
                );
                
            } catch (error) {
                // Enhanced error handling for duplicate key and other errors
                if (error.code === 11000) {
                    ctx.reply('✅ You are already registered as a teacher!', teacherMenu);
                } else {
                    console.error('Error completing teacher registration:', error);
                    ctx.reply('❌ An error occurred during registration. Please try again.');
                }
                
                // Clean up regardless of error
                await OTP.deleteOne({ telegramId: ctx.from.id });
                delete ctx.session.teacherName;
                delete ctx.session.tempPassword;
                delete ctx.session.waitingForConfirmation;
            }
            
            ctx.scene.leave();
            return;
        } 
        else if (text === 'CANCEL') {
            await OTP.deleteOne({ telegramId: ctx.from.id });
            delete ctx.session.teacherName;
            delete ctx.session.tempPassword;
            delete ctx.session.waitingForConfirmation;
            
            ctx.reply('❌ Registration cancelled.', Markup.removeKeyboard());
            ctx.scene.leave();
            return;
        }
        else {
            // If they type something else while waiting for confirmation
            ctx.reply('Please type "CONFIRM" to complete registration or "CANCEL" to abort:');
            return;
        }
    }
    
    // This is the name input handling (original code)
    if (!isValidName(text)) {
        ctx.reply('❌ Invalid name. Please enter a valid name (1-100 characters).');
        return;
    }

    ctx.session.teacherName = text;
    
    // Generate a 6-digit password
    const password = generatePassword();
    ctx.session.tempPassword = password;
    ctx.session.waitingForConfirmation = true;
    
    ctx.reply(
        `🔐 Your auto-generated password is: ${password}\n\n` +
        'Please save this password securely. You will need it to log in.\n\n' +
        'Type "CONFIRM" to complete registration or "CANCEL" to abort:',
        Markup.keyboard([['CONFIRM'], ['CANCEL']]).resize()
    );
});

// Register the scene
stage.register(teacherRegisterNameScene);
// Register the scenes
stage.register(teacherRegisterStartScene);

// Teacher Login Scene
        
        // Verify password

// Teacher Login Scene - Fixed to properly set user role
const teacherLoginScene = new Scenes.BaseScene('teacher_login_scene');

teacherLoginScene.enter((ctx) => {
    ctx.reply(
        '🔐 Teacher Login\n\n' +
        'Please enter your Teacher ID:',
        Markup.keyboard([['❌ Cancel Login']]).resize()
    );
});

teacherLoginScene.on('text', async (ctx) => {
    const text = ctx.message.text.trim();
    
    if (text === '❌ Cancel Login') {
        ctx.reply('❌ Login cancelled.',  postLogoutMenu);
        return ctx.scene.leave();
    }
    
    if (!ctx.session.loginState) {
        // First step: Teacher ID
        if (!isValidTeacherId(text)) {
            ctx.reply('❌ Invalid Teacher ID format. Please enter a valid Teacher ID (e.g., TE1234).');
            return;
        }
        
        const teacher = await Teacher.findOne({ teacherId: text });
        if (!teacher) {
            ctx.reply('❌ Teacher ID not found. Please check and try again.');
            return;
        }
        
        ctx.session.loginState = 'password';
        ctx.session.loginTeacherId = text;
        ctx.reply('Please enter your password:');
    } else if (ctx.session.loginState === 'password') {
        // Second step: Password
        const teacherId = ctx.session.loginTeacherId;
        const password = text;
        
        const teacherLogin = await TeacherLogin.findOne({ teacherId });
        if (!teacherLogin) {
            ctx.reply('❌ Login credentials not found. Please contact an administrator.');
            delete ctx.session.loginState;
            delete ctx.session.loginTeacherId;
            return ctx.scene.leave();
        }
        
        // Check if account is locked
        if (isAccountLocked(teacherLogin.lockedUntil)) {
            const lockTime = Math.ceil((teacherLogin.lockedUntil - new Date()) / 60000); // minutes
            ctx.reply(`❌ Account temporarily locked. Try again in ${lockTime} minutes.`);
            delete ctx.session.loginState;
            delete ctx.session.loginTeacherId;
            return ctx.scene.leave();
        }
             // Teacher Login Scene - Add these action handlers
teacherLoginScene.action('cancel_login', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Login cancelled.',  postLogoutMenu);
    ctx.scene.leave();
});

teacherLoginScene.on('text', async (ctx) => {
    const text = ctx.message.text.trim();
    
    if (text === '❌ Cancel Login') {
        ctx.reply('❌ Login cancelled.',  postLogoutMenu);
        return ctx.scene.leave();
    }
    
    // ... rest of your existing login logic
});
        // Verify password
        if (!verifyPassword(password, teacherLogin.password)) {
            teacherLogin.loginAttempts += 1;
            
            // Lock account after 3 failed attempts for 15 minutes
            if (teacherLogin.loginAttempts >= 3) {
                teacherLogin.lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
                teacherLogin.loginAttempts = 0;
                await teacherLogin.save();
                
                ctx.reply('❌ Too many failed attempts. Account locked for 15 minutes.');
            } else {
                const remainingAttempts = 3 - teacherLogin.loginAttempts;
                await teacherLogin.save();
                ctx.reply(`❌ Incorrect password. ${remainingAttempts} attempt(s) remaining.`);
            }
            
            return;
        }
        
        // Successful login
        teacherLogin.loginAttempts = 0;
        teacherLogin.lockedUntil = null;
        teacherLogin.lastLogin = new Date();
        await teacherLogin.save();
        


        // ✅ CRITICAL FIX: Update teacher telegramId if different
        const teacher = await Teacher.findOne({ teacherId });
        if (teacher) {
            // Update telegramId if it's different or missing
            if (teacher.telegramId !== ctx.from.id) {
                teacher.telegramId = ctx.from.id;
                await teacher.save();
            }
            
            // ✅ CRITICAL FIX: Ensure user record has correct role
            let user = await getUserById(ctx.from.id);
            if (user) {
                user.role = 'teacher';
                user.name = teacher.name; // Update name if changed
                if (teacher.subjects) {
                    user.subjects = teacher.subjects;
                }
                await user.save();
            } else {
                // Create new user record if it doesn't exist
                user = new User({
                    telegramId: ctx.from.id,
                    username: ctx.from.username || '',
                    name: teacher.name,
                    role: 'teacher',
                    subjects: teacher.subjects || []
                });
                await user.save();
            }
        }
        
        delete ctx.session.loginState;
        delete ctx.session.loginTeacherId;
        
        ctx.reply('✅ Login successful!', teacherMenu);
        ctx.scene.leave();
    }


});


// Register the login scene
stage.register(teacherLoginScene);

// --- Teacher Contact Admin Scene ---
const teacherContactAdminScene = new Scenes.BaseScene('teacher_contact_admin_scene');

teacherContactAdminScene.enter(async (ctx) => {
    try {
        const admins = await getAdmins();
        
        if (admins.length === 0) {
            ctx.reply('❌ No admins found to contact.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create admin selection buttons
        const adminButtons = admins.map(admin => [
            Markup.button.callback(
                `${admin.name} (ID: ${admin.telegramId})`,
                `select_admin_${admin.telegramId}`
            )
        ]);
        
        adminButtons.push([Markup.button.callback('❌ Cancel', 'cancel_contact_admin')]);

        ctx.reply('👑 Select an admin to contact:', Markup.inlineKeyboard(adminButtons));

    } catch (error) {
        console.error('Error in teacher contact admin scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle admin selection
teacherContactAdminScene.action(/^select_admin_(\d+)$/, async (ctx) => {
    const adminId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const admin = await getUserById(adminId);
        if (!admin) {
            ctx.reply('❌ Admin not found.', teacherMenu);
            return ctx.scene.leave();
        }
        
        // Store admin info in session
        ctx.session.contactAdminInfo = {
            adminId: adminId,
            adminName: admin.name
        };

        ctx.reply(
            `📬 You are now messaging **${admin.name}**.\n\n` +
            `Please send your message (text, photo, video, document, audio, or voice):`,
            Markup.keyboard([['❌ Cancel']]).resize()
        );

    } catch (error) {
        console.error('Error selecting admin:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle cancellation
teacherContactAdminScene.action('cancel_contact_admin', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Contact admin cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Handle text cancellation
teacherContactAdminScene.hears('❌ Cancel', async (ctx) => {
    ctx.reply('❌ Contact admin cancelled.', teacherMenu);
    ctx.scene.leave();
});
teacherContactAdminScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
    const contactInfo = ctx.session.contactAdminInfo;
    
    if (!contactInfo) {
        ctx.reply('❌ No admin selected. Please start over.', teacherMenu);
        return ctx.scene.leave();
    }

    const { adminId, adminName } = contactInfo;

    let success = false;
    let errorMessage = '';

    try {
        // Get rich teacher information
        const teacherInfoRich = await getRichTeacherInfo(ctx.from.id);
        if (!teacherInfoRich) {
            ctx.reply('❌ Could not retrieve your teacher information.', teacherMenu);
            delete ctx.session.contactAdminInfo;
            return ctx.scene.leave();
        }

        // Create enhanced teacher info header
        const teacherInfo = `
🧑‍🏫 *Teacher Contact Request:*
━━━━━━━━━━━━━━━━━━━━
• 👤 *Name:* ${teacherInfoRich.name}
• 🆔 *Teacher ID:* ${teacherInfoRich.teacherId}
• 📞 *Telegram ID:* ${teacherInfoRich.telegramId}
${teacherInfoRich.username ? `• 👤 *Username:* @${teacherInfoRich.username}\n` : ''}

📚 *Teaching Subjects:*
${teacherInfoRich.subjects.map(subj => `  • ${subj}`).join('\n') || '  • No subjects assigned'}

📊 *Statistics:*
• 👥 Total Students: ${teacherInfoRich.studentCount}
• 🏆 Top Subject: ${teacherInfoRich.subjectStats[0]?._id || 'N/A'} (${teacherInfoRich.subjectStats[0]?.studentCount || 0} students)

📅 *Registered:* ${new Date(teacherInfoRich.registrationDate).toLocaleDateString()}
━━━━━━━━━━━━━━━━━━━━

💬 *Message from Teacher:*
`;

        // Send appropriate message based on content type
        if (ctx.message.text) {
            // Text message
            await ctx.telegram.sendMessage(
                adminId,
                teacherInfo + ctx.message.text,
                { parse_mode: "HTML" }
            );
            success = true;
        } 
        else if (ctx.message.photo) {
            // Photo with caption and teacher info
            const photo = ctx.message.photo[ctx.message.photo.length - 1];
            const caption = ctx.message.caption 
                ? teacherInfo + ctx.message.caption
                : teacherInfo + '📸 Photo message';
            
            await ctx.telegram.sendPhoto(
                adminId,
                photo.file_id,
                { caption, parse_mode: "HTML" }
            );
            success = true;
        }
        else if (ctx.message.video) {
            // Video with caption and teacher info
            const caption = ctx.message.caption 
                ? teacherInfo + ctx.message.caption
                : teacherInfo + '🎥 Video message';
            
            await ctx.telegram.sendVideo(
                adminId,
                ctx.message.video.file_id,
                { caption, parse_mode: "HTML" }
            );
            success = true;
        }
        else if (ctx.message.document) {
            // Document with caption and teacher info
            const caption = ctx.message.caption 
                ? teacherInfo + ctx.message.caption
                : teacherInfo + '📄 Document message';
            
            await ctx.telegram.sendDocument(
                adminId,
                ctx.message.document.file_id,
                { caption, parse_mode: "HTML" }
            );
            success = true;
        }
        else if (ctx.message.audio) {
            // Audio with caption and teacher info
            const caption = ctx.message.caption 
                ? teacherInfo + ctx.message.caption
                : teacherInfo + '🎵 Audio message';
            
            await ctx.telegram.sendAudio(
                adminId,
                ctx.message.audio.file_id,
                { caption, parse_mode: "HTML" }
            );
            success = true;
        }
        else if (ctx.message.voice) {
            // Voice message with separate teacher info
            await ctx.telegram.sendVoice(
                adminId,
                ctx.message.voice.file_id
            );
            await ctx.telegram.sendMessage(
                adminId,
                teacherInfo + '🗣️ Voice message from teacher',
                { parse_mode: "HTML" }
            );
            success = true;
        }

        if (success) {
            ctx.replyWithHTML(
                `✅ *Message delivered to ${adminName}!*\n\n` +
                `👑 Admin: ${adminName}\n` +
                `📧 Status: ✅ Delivered\n` +
                `⏰ Time: ${new Date().toLocaleTimeString()}\n\n` +
                `_The admin can see your full teacher information below your message._`,
                teacherMenu
            );
        }

    } catch (error) {
        if (error.response?.error_code === 403) {
            errorMessage = '❌ Failed to send message. The admin may have blocked the bot.';
        } else {
            console.error('Error sending message to admin:', error);
            errorMessage = '❌ Failed to send message. Please try again later.';
        }
        ctx.reply(errorMessage, teacherMenu);
    } finally {
        // Clean up session
        delete ctx.session.contactAdminInfo;
        ctx.scene.leave();
    }
});
// Register the scene
stage.register(teacherContactAdminScene);


// Teacher Export Grades Scene
const teacherExportGradesScene = new Scenes.BaseScene('teacher_export_grades_scene');

teacherExportGradesScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `export_grades_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add cancel button
        subjectButtons.push([Markup.button.callback('❌ Cancel Export', 'cancel_export_grades')]);

        ctx.reply('📚 Select a subject to export grades from:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in export grades scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
teacherExportGradesScene.action(/^export_grades_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get all grades for this subject
        const grades = await Grade.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1, date: -1 });

        if (grades.length === 0) {
            ctx.reply(`❌ No grades found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Group grades by student
        const gradesByStudent = {};
        grades.forEach(grade => {
            if (!gradesByStudent[grade.studentId]) {
                gradesByStudent[grade.studentId] = {
                    studentName: grade.studentName,
                    grades: []
                };
            }
            gradesByStudent[grade.studentId].grades.push(grade);
        });

        // Generate the grade report
        const reportContent = generateGradeReport(subject, teacher.name, gradesByStudent);
        
        // Create temporary file
        const tempDir = './temp_exports';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        
        const fileName = `grades_${subject.replace(/ /g, '_')}_${new Date().toISOString().split('T')[0]}.txt`;
        const filePath = path.join(tempDir, fileName);
        
        fs.writeFileSync(filePath, reportContent);

        // Send the file
        await ctx.replyWithDocument({
            source: filePath,
            filename: fileName,
            caption: `📊 Grade report for ${subject} (${grades.length} grades)`
        });

        // Clean up
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        ctx.reply('✅ Grade export completed!', teacherMenu);

    } catch (error) {
        console.error('Error exporting grades:', error);
        ctx.reply('❌ An error occurred while exporting grades.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Handle cancellation
teacherExportGradesScene.action('cancel_export_grades', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Grade export cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Handle text cancellation
teacherExportGradesScene.hears('❌ Cancel Export', async (ctx) => {
    ctx.reply('❌ Grade export cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Add this to the export grades scene for multiple format options
teacherExportGradesScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `export_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add cancel button
        subjectButtons.push([Markup.button.callback('❌ Cancel Export', 'cancel_export_grades')]);

        ctx.reply('📚 Select a subject to export grades from:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in export grades scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Update the subject selection handler to include format options
teacherExportGradesScene.action(/^export_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    // Store selected subject
    ctx.session.exportSubject = subject;

    // Ask for format selection
    ctx.reply(
        `📊 Select export format for ${subject}:`,
        Markup.inlineKeyboard([
            [Markup.button.callback('📝 Text Report', `export_format_text_${subject.replace(/ /g, '_')}`)],
            [Markup.button.callback('📊 CSV Format', `export_format_csv_${subject.replace(/ /g, '_')}`)],
            [Markup.button.callback('❌ Cancel', 'cancel_export_grades')]
        ])
    );
});

// Handle format selection
teacherExportGradesScene.action(/^export_format_(text|csv)_(.+)$/, async (ctx) => {
    const format = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get all grades for this subject
        const grades = await Grade.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1, date: -1 });

        if (grades.length === 0) {
            ctx.reply(`❌ No grades found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        let fileContent;
        let fileName;
        let caption;

        if (format === 'text') {
            // Group grades by student for text report
            const gradesByStudent = {};
            grades.forEach(grade => {
                if (!gradesByStudent[grade.studentId]) {
                    gradesByStudent[grade.studentId] = {
                        studentName: grade.studentName,
                        grades: []
                    };
                }
                gradesByStudent[grade.studentId].grades.push(grade);
            });

            fileContent = generateGradeReport(subject, teacher.name, gradesByStudent);
            fileName = `grades_${subject.replace(/ /g, '_')}_${new Date().toISOString().split('T')[0]}.txt`;
            caption = `📊 Grade report for ${subject} (${grades.length} grades)`;
        } else {
            // CSV format
            fileContent = generateGradeCSV(subject, teacher.name, grades);
            fileName = `grades_${subject.replace(/ /g, '_')}_${new Date().toISOString().split('T')[0]}.csv`;
            caption = `📊 Grade data for ${subject} (${grades.length} records)`;
        }

        // Create temporary file
        const tempDir = './temp_exports';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        
        const filePath = path.join(tempDir, fileName);
        fs.writeFileSync(filePath, fileContent);

        // Send the file
        await ctx.replyWithDocument({
            source: filePath,
            filename: fileName,
            caption: caption
        });

        // Clean up
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        ctx.reply('✅ Grade export completed!', teacherMenu);

    } catch (error) {
        console.error('Error exporting grades:', error);
        ctx.reply('❌ An error occurred while exporting grades.', teacherMenu);
    }
    
    delete ctx.session.exportSubject;
    ctx.scene.leave();
});

// Helper function to generate CSV format
const generateGradeCSV = (subject, teacherName, grades) => {
    let csv = 'Student ID,Student Name,Subject,Score,Purpose,Date,Comments,Teacher\n';
    
    grades.forEach(grade => {
        const row = [
            grade.studentId,
            `"${grade.studentName.replace(/"/g, '""')}"`,
            `"${subject.replace(/"/g, '""')}"`,
            grade.score,
            `"${grade.purpose.replace(/"/g, '""')}"`,
            new Date(grade.date).toISOString().split('T')[0],
            grade.comments ? `"${grade.comments.replace(/"/g, '""')}"` : '',
            `"${teacherName.replace(/"/g, '""')}"`
        ];
        csv += row.join(',') + '\n';
    });

    return csv;
};

// Enhanced grade report generator
const generateGradeReport = (subject, teacherName, gradesByStudent) => {
    let report = `GRADE REPORT - ${subject.toUpperCase()}\n`;
    report += '='.repeat(80) + '\n\n';
    report += `Teacher: ${teacherName}\n`;
    report += `Subject: ${subject}\n`;
    report += `Report Date: ${new Date().toLocaleDateString()}\n`;
    report += `Generated: ${new Date().toLocaleString()}\n`;
    report += '='.repeat(80) + '\n\n';

    let totalStudents = Object.keys(gradesByStudent).length;
    let totalGrades = 0;
    let classTotal = 0;

    // Add student grades
    for (const [studentId, studentData] of Object.entries(gradesByStudent)) {
        report += `STUDENT: ${studentData.studentName}\n`;
        report += `ID: ${studentId}\n`;
        report += '-'.repeat(60) + '\n';
        
        report += 'No. Purpose         Score   Date         Comments\n';
        report += '-'.repeat(60) + '\n';

        let studentTotal = 0;
        let gradeCount = 0;

        studentData.grades.forEach((grade, index) => {
            const purpose = grade.purpose.padEnd(12);
            const score = grade.score.toString().padStart(5);
            const date = new Date(grade.date).toLocaleDateString().padEnd(12);
            const comments = grade.comments ? grade.comments.substring(0, 20) + (grade.comments.length > 20 ? '...' : '') : '';
            
            report += `${(index + 1).toString().padStart(2)}. ${purpose} ${score}%  ${date} ${comments}\n`;

            studentTotal += grade.score;
            gradeCount++;
            totalGrades++;
        });

        // Calculate student average
        if (gradeCount > 0) {
            const average = studentTotal / gradeCount;
            classTotal += average;
            report += '-'.repeat(60) + '\n';
            report += `AVERAGE: ${average.toFixed(2)}%\n`;
            report += `GRADES: ${gradeCount}\n`;
        }

        report += '='.repeat(60) + '\n\n';
    }

    // Add class statistics
    if (totalStudents > 0) {
        const classAverage = classTotal / totalStudents;
        
        report += 'CLASS STATISTICS\n';
        report += '='.repeat(40) + '\n';
        report += `Total Students: ${totalStudents}\n`;
        report += `Total Grades: ${totalGrades}\n`;
        report += `Class Average: ${classAverage.toFixed(2)}%\n`;
        report += `Subject: ${subject}\n`;
        report += `Teacher: ${teacherName}\n`;
        report += `Report Generated: ${new Date().toLocaleString()}\n`;
        report += '='.repeat(40) + '\n';
    }

    return report;
};
// Add this error handling function
const safeFileOperation = async (ctx, filePath, operation) => {
    try {
        return await operation();
    } catch (error) {
        console.error('File operation error:', error);
        ctx.reply('❌ Error creating export file. Please try again.', teacherMenu);
        
        // Clean up if file was created but couldn't be sent
        if (fs.existsSync(filePath)) {
            try {
                fs.unlinkSync(filePath);
            } catch (unlinkError) {
                console.error('Error cleaning up file:', unlinkError);
            }
        }
        
        throw error;
    }
};
// Register the scene
stage.register(teacherExportGradesScene);
// Teacher Search Student Scene
const teacherSearchStudentScene = new Scenes.BaseScene('teacher_search_student_scene');

teacherSearchStudentScene.enter((ctx) => {
    const cancelKeyboard = Markup.keyboard([
        ['❌ Cancel Search']
    ]).resize();

    ctx.reply(
        '🔍 Search students in your database:\n\n' +
        'You can search by:\n' +
        '• Student ID (e.g., ST1234)\n' +
        '• Student Name (full or partial)\n\n' +
        'Enter your search query:',
        cancelKeyboard
    );
});

teacherSearchStudentScene.on('text', async (ctx) => {
    const query = ctx.message.text.trim();
    
    if (query === '❌ Cancel Search') {
        ctx.reply('❌ Search cancelled.', teacherMenu);
        delete ctx.session.searchResults;
        delete ctx.session.currentPage;
        return ctx.scene.leave();
    }

    if (!query) {
        ctx.reply('❌ Please enter a search query.');
        return;
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Search in teacher's database
        const searchResults = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            $or: [
                { studentId: { $regex: query, $options: 'i' } },
                { studentName: { $regex: query, $options: 'i' } }
            ]
        }).sort({ studentName: 1 });

        if (searchResults.length === 0) {
            ctx.reply('❌ No students found matching your search.', teacherMenu);
            return ctx.scene.leave();
        }

        // Store search results and pagination info
        ctx.session.searchResults = searchResults;
        ctx.session.currentPage = 0;
        ctx.session.totalPages = Math.ceil(searchResults.length / 5);

        // Display first page of results
        await displaySearchResults(ctx);

    } catch (error) {
        console.error('Error searching students:', error);
        ctx.reply('❌ An error occurred while searching.', teacherMenu);
        ctx.scene.leave();
    }
});



// Handle pagination actions
teacherSearchStudentScene.action('search_prev_page', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.currentPage--;
    await displaySearchResults(ctx);
});

teacherSearchStudentScene.action('search_next_page', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.currentPage++;
    await displaySearchResults(ctx);
});

teacherSearchStudentScene.action('search_done', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('✅ Search completed.', teacherMenu);
    delete ctx.session.searchResults;
    delete ctx.session.currentPage;
    delete ctx.session.totalPages;
    ctx.scene.leave();
});

teacherSearchStudentScene.action('search_new', async (ctx) => {
    await ctx.answerCbQuery();
    delete ctx.session.searchResults;
    delete ctx.session.currentPage;
    delete ctx.session.totalPages;
    ctx.scene.reenter();
});

// Handle cancellation from text
teacherSearchStudentScene.hears('❌ Cancel Search', async (ctx) => {
    ctx.reply('❌ Search cancelled.', teacherMenu);
    delete ctx.session.searchResults;
    delete ctx.session.currentPage;
    delete ctx.session.totalPages;
    ctx.scene.leave();
});

// Handle unsupported messages
teacherSearchStudentScene.on('message', (ctx) => {
    if (ctx.message.text !== '❌ Cancel Search') {
        ctx.reply('❌ Please enter a valid search query or use the cancel button.');
    }
});
// Add this to the search scene to handle individual student selection
teacherSearchStudentScene.action(/^view_student_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        if (!studentRelation) {
            ctx.reply('❌ Student not found.', teacherMenu);
            return;
        }

        const studentData = await getStudentById(studentId);
        const parent = studentData && studentData.parentId 
            ? await getUserById(studentData.parentId) 
            : null;

        let message = `📋 *Student Details*\n\n`;
        message += `👤 *Name:* ${studentRelation.studentName}\n`;
        message += `🆔 *ID:* ${studentRelation.studentId}\n`;
        message += `📚 *Subject:* ${studentRelation.subject}\n`;
        message += `🏫 *Class:* ${studentRelation.className}\n\n`;

        if (parent) {
            message += `👨‍👩‍👧‍👦 *Parent Information:*\n`;
            message += `   • Name: ${parent.name}\n`;
            message += `   • Telegram ID: ${parent.telegramId}\n`;
            if (parent.username) {
                message += `   • Username: @${parent.username}\n`;
            }
        } else {
            message += `❌ *No parent linked*\n`;
        }

        message += `\n📅 *Added to your class:* ${new Date(studentRelation.addedDate).toLocaleDateString()}`;

        // Create action buttons
        const actionButtons = [
            [Markup.button.callback('💬 Contact Parent', `contact_${studentId}`)],
            [Markup.button.callback('🗑️ Remove from Class', `remove_${studentId}`)],
            [Markup.button.callback('⬅️ Back to Results', 'back_to_results')]
        ];

        ctx.replyWithHTML(message, Markup.inlineKeyboard(actionButtons));

    } catch (error) {
        console.error('Error viewing student details:', error);
        ctx.reply('❌ An error occurred.', teacherMenu);
    }
});

// Update the displaySearchResults function to include view buttons
const displaySearchResults = async (ctx) => {
    const { searchResults, currentPage, totalPages } = ctx.session;
    const startIndex = currentPage * 5;
    const endIndex = Math.min(startIndex + 5, searchResults.length);
    const currentResults = searchResults.slice(startIndex, endIndex);

    let message = `🔍 *Search Results (${searchResults.length} found)*\n\n`;
    
    // Display current page results with view buttons
    const viewButtons = [];
    
    for (let i = 0; i < currentResults.length; i++) {
        const student = currentResults[i];
        const studentData = await getStudentById(student.studentId);
        const parentInfo = studentData && studentData.parentId 
            ? `👨‍👩‍👧‍👦 Parent: Linked` 
            : '👨‍👩‍👧‍👦 No parent';
        
        message += `*${startIndex + i + 1}. ${student.studentName}*\n`;
        message += `   🆔 ID: ${student.studentId}\n`;
        message += `   📚 Subject: ${student.subject}\n`;
        message += `   🏫 Class: ${student.className}\n`;
        message += `   ${parentInfo}\n\n`;

        // Add view button for each student
        viewButtons.push([Markup.button.callback(
            `👀 View ${student.studentName}`,
            `view_student_${student.studentId}`
        )]);
    }

    message += `📄 Page ${currentPage + 1} of ${totalPages}\n\n`;

    // Create pagination buttons
    const paginationButtons = [];

    if (currentPage > 0) {
        paginationButtons.push(Markup.button.callback('⬅️ Previous', 'search_prev_page'));
    }

    if (currentPage < totalPages - 1) {
        paginationButtons.push(Markup.button.callback('Next ➡️', 'search_next_page'));
    }

    paginationButtons.push(Markup.button.callback('✅ Done', 'search_done'));
    paginationButtons.push(Markup.button.callback('🔄 New Search', 'search_new'));

    // Combine all buttons
    const allButtons = [...viewButtons, paginationButtons];

    ctx.replyWithHTML(message, Markup.inlineKeyboard(allButtons));
};

// Add action handlers for student actions
teacherSearchStudentScene.action(/^contact_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        const studentData = await getStudentById(studentId);
        
        if (!studentData || !studentData.parentId) {
            ctx.reply('❌ Student has no linked parent.', teacherMenu);
            return;
        }

        // Store contact info and switch to message mode
        ctx.session.contactInfo = {
            studentId: studentId,
            studentName: studentRelation.studentName,
            parentId: studentData.parentId,
            subject: studentRelation.subject
        };

        const parent = await getUserById(studentData.parentId);
        const parentName = parent ? parent.name : 'Parent';

        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel Message']
        ]).resize();

        ctx.reply(
            `📞 Ready to contact ${parentName}, parent of ${studentRelation.studentName}:\n\n` +
            `Please type your message:`,
            cancelKeyboard
        );

    } catch (error) {
        console.error('Error preparing contact:', error);
        ctx.reply('❌ An error occurred.', teacherMenu);
    }
});

teacherSearchStudentScene.action(/^remove_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        ctx.reply(
            `⚠️ *Confirm Removal*\n\n` +
            `Are you sure you want to remove ${studentRelation.studentName} (${studentId}) ` +
            `from your ${studentRelation.subject} class?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Remove', `confirm_remove_${studentId}`)],
                [Markup.button.callback('❌ No, Cancel', 'back_to_results')]
            ])
        );

    } catch (error) {
        console.error('Error preparing removal:', error);
        ctx.reply('❌ An error occurred.', teacherMenu);
    }
});

teacherSearchStudentScene.action(/^confirm_remove_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        await TeacherStudent.deleteOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: studentRelation.subject
        });

        ctx.reply(
            `✅ Successfully removed ${studentRelation.studentName} from your ${studentRelation.subject} class.`,
            teacherMenu
        );

        // Clean up and return to menu
        delete ctx.session.searchResults;
        delete ctx.session.currentPage;
        delete ctx.session.totalPages;
        ctx.scene.leave();

    } catch (error) {
        console.error('Error removing student:', error);
        ctx.reply('❌ An error occurred while removing the student.', teacherMenu);
    }
});

teacherSearchStudentScene.action('back_to_results', async (ctx) => {
    await ctx.answerCbQuery();
    await displaySearchResults(ctx);
});

// Handle message sending from search results
teacherSearchStudentScene.on('text', async (ctx) => {
    const message = ctx.message.text.trim();
    
    if (message === '❌ Cancel Message') {
        ctx.reply('❌ Message cancelled.', teacherMenu);
        delete ctx.session.contactInfo;
        return;
    }

    const contactInfo = ctx.session.contactInfo;
    if (!contactInfo) {
        return; // Not in message sending mode
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const parent = await getUserById(contactInfo.parentId);
        
        // Send message to parent
        await ctx.telegram.sendMessage(
            contactInfo.parentId,
            `📞 *Message from ${teacher.name} (${contactInfo.subject} Teacher):*\n${message}`,
            { parse_mode: "HTML" }
        );

        ctx.reply(
            `✅ Message sent to ${parent.name}, parent of ${contactInfo.studentName}.`,
            teacherMenu
        );

    } catch (error) {
        if (error.response?.error_code === 403) {
            ctx.reply('❌ Failed to send message. The parent may have blocked the bot.', teacherMenu);
        } else {
            console.error('Error sending message:', error);
            ctx.reply('❌ An error occurred while sending the message.', teacherMenu);
        }
    }
    
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});
// Register the scene
stage.register(teacherSearchStudentScene);

// Teacher Contact Parent Scene (Fixed for teacher not defined)
const teacherContactParentScene = new Scenes.BaseScene('teacher_contact_parent_scene');

teacherContactParentScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Clear any prior session data
        ctx.session.contactStudentId = null;
        ctx.session.contactStudentName = null;
        ctx.session.contactParentId = null;
        ctx.session.contactParentName = null;

        ctx.replyWithHTML(
            '💬 *Contact a Parent*\n\n' +
            'Enter the Student ID to contact their parent:\n\n' +
            '📋 *Format:* ST1234 or ST-1234\n' +
            '💡 *Tip:* Use the student ID from your class list.',
            Markup.keyboard([['❌ Cancel']]).resize()
        );

    } catch (error) {
        console.error('Error entering contact parent scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

teacherContactParentScene.on('text', async (ctx) => {
    const input = ctx.message.text.trim().toUpperCase(); // Trim and normalize to uppercase for consistency

    if (input === '❌ CANCEL') {
        ctx.reply('❌ Contact cancelled.', teacherMenu);
        ctx.session.contactStudentId = null;
        ctx.session.contactStudentName = null;
        ctx.session.contactParentId = null;
        ctx.session.contactParentName = null;
        return ctx.scene.leave();
    }

    // If session has contactStudentId, this is a message input
    if (ctx.session.contactStudentId) {
        const messageText = ctx.message.text.trim();

        if (messageText.toUpperCase() === '❌ CANCEL') {
            ctx.reply('❌ Message cancelled.', teacherMenu);
            // Clear session
            ctx.session.contactStudentId = null;
            ctx.session.contactStudentName = null;
            ctx.session.contactParentId = null;
            ctx.session.contactParentName = null;
            return ctx.scene.leave();
        }

        if (!messageText || messageText.length === 0) {
            return ctx.reply('❌ Please enter a valid message (cannot be empty).');
        }

        if (messageText.length > 500) {
            return ctx.reply('❌ Message too long. Keep it under 500 characters.');
        }

        try {
            // Re-fetch teacher to avoid undefined error
            const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
            if (!teacher) {
                ctx.reply('❌ Teacher profile not found.', teacherMenu);
                return ctx.scene.leave();
            }

            const { contactParentId, contactStudentName, contactStudentId } = ctx.session;

            // Send message to parent
            await ctx.telegram.sendMessage(
                contactParentId,
                `📩 *Message from Teacher*\n\n` +
                `👨‍🏫 From: ${teacher.name} (${teacher.teacherId})\n` +
                `👨‍🎓 About Student: ${contactStudentName} (ID: ${contactStudentId})\n` +
                `💬 Message: ${messageText}\n\n` +
                `📅 Sent: ${new Date().toLocaleString()}`,
                { parse_mode: 'HTML' }
            );

            // Confirm to teacher
            ctx.replyWithHTML(
                `✅ *Message Sent Successfully!*\n\n` +
                `👨‍👩‍👧 To Parent: ${ctx.session.contactParentName}\n` +
                `👨‍🎓 Student: ${contactStudentName}\n` +
                `💬 Your message has been delivered.`,
                teacherMenu
            );

            // Log the contact
            await trackAdminActivity(ctx, 'teacher_contact_parent_sent', {
                teacherId: teacher.teacherId,
                teacherName: teacher.name,
                studentId: contactStudentId,
                parentId: contactParentId,
                messagePreview: messageText.substring(0, 100) + '...'
            });

            // Clear session
            ctx.session.contactStudentId = null;
            ctx.session.contactStudentName = null;
            ctx.session.contactParentId = null;
            ctx.session.contactParentName = null;

            ctx.scene.leave();

        } catch (error) {
            console.error('Error sending message to parent:', error);
            if (error.code === 403) {
                ctx.reply('❌ Failed to send message. The parent may have blocked the bot or restricted messages.');
            } else {
                ctx.reply('❌ An error occurred while sending the message. Please try again.');
            }
            ctx.scene.leave();
        }
        return;
    }

    // Otherwise, this is a student ID input
    // Step 1: Validate format
    const normalizedId = input.replace(/-/g, '');
    if (!/^ST\d{4}$/i.test(normalizedId)) {
        return ctx.replyWithHTML(
            '❌ *Invalid Student ID Format*\n\n' +
            'Please enter a valid ID like: ST1234 or ST-1234\n\n' +
            'Try again:'
        );
    }

    // Step 2: Check if student exists and is linked to this teacher
    const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
    if (!teacher) {
        ctx.reply('❌ Teacher profile not found.', teacherMenu);
        return ctx.scene.leave();
    }

    const student = await Student.findOne({ studentId: normalizedId });
    if (!student) {
        return ctx.replyWithHTML(
            `❌ *Student ID Not Found*\n\n` +
            `No student with ID "${normalizedId}" exists in the database.\n\n` +
            'Please check the ID and try again:'
        );
    }

    // Step 3: Verify teacher-student relationship
    const relation = await TeacherStudent.findOne({
        teacherId: teacher.teacherId,
        studentId: normalizedId
    });
    if (!relation) {
        return ctx.replyWithHTML(
            `❌ *Access Denied*\n\n` +
            `Student "${student.name}" (ID: ${normalizedId}) is not in your class list.\n\n` +
            'You can only contact parents of your assigned students.'
        );
    }

    // Step 4: Check if parent is linked
    if (!student.parentId) {
        return ctx.replyWithHTML(
            `❌ *No Parent Linked*\n\n` +
            `Student "${student.name}" (ID: ${normalizedId}) does not have a linked parent.\n\n` +
            'Contact an admin to link a parent first.'
        );
    }

    // Fetch parent details
    const parent = await User.findOne({ telegramId: student.parentId });
    if (!parent) {
        return ctx.replyWithHTML(
            `❌ *Parent Not Found*\n\n` +
            `A parent is linked to "${student.name}" but their profile is invalid.\n\n` +
            'Contact an admin to fix this.'
        );
    }

    // Store in session for next step
    ctx.session.contactStudentId = normalizedId;
    ctx.session.contactStudentName = student.name;
    ctx.session.contactParentId = parent.telegramId;
    ctx.session.contactParentName = parent.name;

    ctx.replyWithHTML(
        `✅ *Student Found*\n\n` +
        `👨‍🎓 Student: ${student.name} (ID: ${normalizedId})\n` +
        `👨‍👩‍👧 Parent: ${parent.name}\n\n` +
        'Now, type your message to send to the parent:',
        Markup.keyboard([['❌ Cancel']]).resize()
    );

    // Track activity
    await trackAdminActivity(ctx, 'teacher_contact_parent_init', {
        teacherId: teacher.teacherId,
        studentId: normalizedId,
        parentId: parent.telegramId
    });
});




// Contact by ID Scene
const contactParentByIdScene = new Scenes.BaseScene('contact_parent_by_id_scene');

contactParentByIdScene.enter((ctx) => {
    const cancelKeyboard = Markup.keyboard([
        ['❌ Cancel Operation']
    ]).resize();

    ctx.reply('🆔 Please enter the Student ID to contact their parent:', cancelKeyboard);
});

contactParentByIdScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    
    if (studentId === '❌ Cancel Operation') {
        ctx.reply('❌ Contact parent cancelled.', teacherMenu);
        return ctx.scene.leave();
    }

    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a valid student ID (e.g., ST1234).');
        return;
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Check if student exists in teacher's database
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        if (!studentRelation) {
            ctx.reply('❌ Student not found in your database. Please check the Student ID.', teacherMenu);
            return ctx.scene.leave();
        }

        // Get student details from main database
        const student = await getStudentById(studentId);
        if (!student || !student.parentId) {
            ctx.reply('❌ Student has no linked parent or parent not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Get parent details
        const parent = await getUserById(student.parentId);
        if (!parent) {
            ctx.reply('❌ Parent not found for this student.', teacherMenu);
            return ctx.scene.leave();
        }

        // Store contact info in session
        ctx.session.contactInfo = {
            studentId: studentId,
            studentName: studentRelation.studentName,
            parentId: student.parentId,
            parentName: parent.name,
            subject: studentRelation.subject
        };

        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel Message']
        ]).resize();

        ctx.reply(
            `📞 Ready to contact parent of ${studentRelation.studentName}:\n\n` +
            `👤 Student: ${studentRelation.studentName} (${studentId})\n` +
            `📚 Subject: ${studentRelation.subject}\n` +
            `👨‍👩‍👧‍👦 Parent: ${parent.name}\n\n` +
            `Please type your message to send to the parent:`,
            cancelKeyboard
        );

    } catch (error) {
        console.error('Error processing student ID:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

contactParentByIdScene.on('text', async (ctx) => {
    const message = ctx.message.text.trim();
    
    if (message === '❌ Cancel Message') {
        ctx.reply('❌ Message cancelled.', teacherMenu);
        delete ctx.session.contactInfo;
        return ctx.scene.leave();
    }

    const contactInfo = ctx.session.contactInfo;
    if (!contactInfo) {
        ctx.reply('❌ Contact information not found. Please start over.', teacherMenu);
        return ctx.scene.leave();
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Send message to parent
        await ctx.telegram.sendMessage(
            contactInfo.parentId,
            `📞 *Message from ${teacher.name} (${contactInfo.subject} Teacher):*\n${message}`,
            { parse_mode: "HTML" }
        );

        ctx.reply(
            `✅ Message sent to ${contactInfo.parentName}, parent of ${contactInfo.studentName}.`,
            teacherMenu
        );

    } catch (error) {
        if (error.response?.error_code === 403) {
            ctx.reply('❌ Failed to send message. The parent may have blocked the bot.', teacherMenu);
        } else {
            console.error('Error sending message:', error);
            ctx.reply('❌ An error occurred while sending the message.', teacherMenu);
        }
    }
    
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});

contactParentByIdScene.hears('❌ Cancel Operation', async (ctx) => {
    ctx.reply('❌ Contact parent cancelled.', teacherMenu);
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});
// Contact by List Scene
const contactParentByListScene = new Scenes.BaseScene('contact_parent_by_list_scene');

contactParentByListScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get subjects that have students
        const subjectsWithStudents = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: { _id: '$subject', count: { $sum: 1 } } },
            { $match: { count: { $gt: 0 } } }
        ]);

        if (subjectsWithStudents.length === 0) {
            ctx.reply('❌ You have no students in any subjects.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = subjectsWithStudents.map(subject => 
            [Markup.button.callback(`${subject._id} (${subject.count} students)`, `contact_from_subject_${subject._id.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_contact_list')]);

        ctx.reply('📚 Select a subject to contact parents from:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in contact by list scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
contactParentByListScene.action(/^contact_from_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this subject with parent information
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1 });

        if (students.length === 0) {
            ctx.reply(`❌ No students found in ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Get parent information for each student
        const studentsWithParents = await Promise.all(
            students.map(async (student) => {
                const studentData = await getStudentById(student.studentId);
                const hasParent = studentData && studentData.parentId;
                return {
                    ...student.toObject(),
                    hasParent: hasParent,
                    parentId: hasParent ? studentData.parentId : null
                };
            })
        );

        // Filter out students without parents
        const studentsWithValidParents = studentsWithParents.filter(s => s.hasParent);

        if (studentsWithValidParents.length === 0) {
            ctx.reply(`❌ No students in ${subject} have linked parents.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Create student buttons
        const studentButtons = studentsWithValidParents.map(student => 
            [Markup.button.callback(
                `${student.studentName} (${student.studentId})`, 
                `contact_parent_${student.studentId}_${subject.replace(/ /g, '_')}`
            )]
        );
        
        // Add back and cancel buttons
        studentButtons.push(
            [Markup.button.callback('⬅️ Back to Subjects', 'back_to_subjects_contact')],
            [Markup.button.callback('❌ Cancel', 'cancel_contact_list')]
        );

        ctx.reply(
            `👥 Students in ${subject} with parents:\n\n` +
            `Select a student to contact their parent:`,
            Markup.inlineKeyboard(studentButtons)
        );

    } catch (error) {
        console.error('Error selecting subject:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle student selection for contact
contactParentByListScene.action(/^contact_parent_(.+)_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get student and parent details
        const student = await getStudentById(studentId);
        const parent = await getUserById(student.parentId);
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        if (!student || !parent || !studentRelation) {
            ctx.reply('❌ Student or parent information not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Store contact info in session
        ctx.session.contactInfo = {
            studentId: studentId,
            studentName: studentRelation.studentName,
            parentId: student.parentId,
            parentName: parent.name,
            subject: subject
        };

        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel Message']
        ]).resize();

        ctx.reply(
            `📞 Ready to contact parent of ${studentRelation.studentName}:\n\n` +
            `👤 Student: ${studentRelation.studentName} (${studentId})\n` +
            `📚 Subject: ${subject}\n` +
            `👨‍👩‍👧‍👦 Parent: ${parent.name}\n\n` +
            `Please type your message to send to the parent:`,
            cancelKeyboard
        );

    } catch (error) {
        console.error('Error selecting student:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle message sending for list contact
contactParentByListScene.on('text', async (ctx) => {
    const message = ctx.message.text.trim();
    
    if (message === '❌ Cancel Message') {
        ctx.reply('❌ Message cancelled.', teacherMenu);
        delete ctx.session.contactInfo;
        return ctx.scene.leave();
    }

    const contactInfo = ctx.session.contactInfo;
    if (!contactInfo) {
        return; // Not in message sending mode
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Send message to parent
        await ctx.telegram.sendMessage(
            contactInfo.parentId,
            `📞 *Message from ${teacher.name} (${contactInfo.subject} Teacher):*\n${message}`,
            { parse_mode: "HTML" }
        );

        ctx.reply(
            `✅ Message sent to ${contactInfo.parentName}, parent of ${contactInfo.studentName}.`,
            teacherMenu
        );

    } catch (error) {
        if (error.response?.error_code === 403) {
            ctx.reply('❌ Failed to send message. The parent may have blocked the bot.', teacherMenu);
        } else {
            console.error('Error sending message:', error);
            ctx.reply('❌ An error occurred while sending the message.', teacherMenu);
        }
    }
    
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});

// Handle back to subjects
contactParentByListScene.action('back_to_subjects_contact', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter(); // Go back to subject selection
});

// Handle cancellation
contactParentByListScene.action('cancel_contact_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Contact parent cancelled.', teacherMenu);
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});
// Register the scenes
stage.register(teacherContactParentScene);
stage.register(contactParentByIdScene);
stage.register(contactParentByListScene);
// Teacher Remove Student Scene
const teacherRemoveStudentScene = new Scenes.BaseScene('teacher_remove_student_scene');

teacherRemoveStudentScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Check if teacher has any students
        const studentCount = await TeacherStudent.countDocuments({ teacherId: teacher.teacherId });
        
        if (studentCount === 0) {
            ctx.reply('❌ You have no students in your database.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create removal option buttons
        ctx.reply(
            '🗑️ How would you like to remove students?',
            Markup.inlineKeyboard([
                [Markup.button.callback('🆔 Remove by Student ID', 'remove_by_id')],
                [Markup.button.callback('📋 Remove from Subject List', 'remove_by_list')],
                [Markup.button.callback('❌ Cancel', 'cancel_remove_student')]
            ])
        );

    } catch (error) {
        console.error('Error in teacher remove student scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});
// Action handlers for teacher remove student scene
teacherRemoveStudentScene.action('remove_by_id', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('remove_student_by_id_scene');
});

teacherRemoveStudentScene.action('remove_by_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('remove_student_by_list_scene');
});

teacherRemoveStudentScene.action('cancel_remove_student', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Student removal cancelled.', teacherMenu);
    ctx.scene.leave();
});
// Remove by ID Scene
const removeStudentByIdScene = new Scenes.BaseScene('remove_student_by_id_scene');

removeStudentByIdScene.enter((ctx) => {
    const cancelKeyboard = Markup.keyboard([
        ['❌ Cancel Operation']
    ]).resize();

    ctx.reply('🆔 Please enter the Student ID to remove from your database:', cancelKeyboard);
});

removeStudentByIdScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    
    if (studentId === '❌ Cancel Operation') {
        ctx.reply('❌ Student removal cancelled.', teacherMenu);
        return ctx.scene.leave();
    }

    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a valid student ID (e.g., ST1234).');
        return;
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Check if student exists in teacher's database
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        if (!studentRelation) {
            ctx.reply('❌ Student not found in your database. Please check the Student ID.', teacherMenu);
            return ctx.scene.leave();
        }

        // Store student info for confirmation
        ctx.session.studentToRemove = {
            studentId: studentId,
            studentName: studentRelation.studentName,
            subject: studentRelation.subject
        };

        // Ask for confirmation
        ctx.reply(
            `⚠️ *Confirm Removal*\n\n` +
            `Are you sure you want to remove ${studentRelation.studentName} (${studentId}) ` +
            `from your ${studentRelation.subject} class?\n\n` +
            `*This will only remove them from your database, not from the school system.*`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Remove', 'confirm_remove_by_id')],
                [Markup.button.callback('❌ No, Cancel', 'cancel_remove_operation')]
            ])
        );

    } catch (error) {
        console.error('Error processing student ID:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

removeStudentByIdScene.action('confirm_remove_by_id', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, subject } = ctx.session.studentToRemove;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        // Remove the student from teacher's database
        await TeacherStudent.deleteOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        ctx.reply(
            `✅ Successfully removed ${studentName} (${studentId}) from your ${subject} class.`,
            teacherMenu
        );

    } catch (error) {
        console.error('Error removing student:', error);
        ctx.reply('❌ An error occurred while removing the student.', teacherMenu);
    }
    
    delete ctx.session.studentToRemove;
    ctx.scene.leave();
});

removeStudentByIdScene.action('cancel_remove_operation', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Student removal cancelled.', teacherMenu);
    delete ctx.session.studentToRemove;
    ctx.scene.leave();
});

removeStudentByIdScene.hears('❌ Cancel Operation', async (ctx) => {
    ctx.reply('❌ Student removal cancelled.', teacherMenu);
    delete ctx.session.studentToRemove;
    ctx.scene.leave();
});
// Remove by List Scene
const removeStudentByListScene = new Scenes.BaseScene('remove_student_by_list_scene');

removeStudentByListScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get subjects that have students
        const subjectsWithStudents = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: { _id: '$subject', count: { $sum: 1 } } },
            { $match: { count: { $gt: 0 } } }
        ]);

        if (subjectsWithStudents.length === 0) {
            ctx.reply('❌ You have no students in any subjects.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = subjectsWithStudents.map(subject => 
            [Markup.button.callback(`${subject._id} (${subject.count} students)`, `remove_from_subject_${subject._id.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_remove_list')]);

        ctx.reply('📚 Select a subject to remove students from:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in remove by list scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
removeStudentByListScene.action(/^remove_from_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this subject
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1 });

        if (students.length === 0) {
            ctx.reply(`❌ No students found in ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Create student buttons (grouped to avoid too many buttons)
        const studentButtons = students.map(student => 
            [Markup.button.callback(
                `${student.studentName} (${student.studentId})`, 
                `remove_student_${student.studentId}_${subject.replace(/ /g, '_')}`
            )]
        );
        
        // Add back and cancel buttons
        studentButtons.push(
            [Markup.button.callback('⬅️ Back to Subjects', 'back_to_subjects_list')],
            [Markup.button.callback('❌ Cancel', 'cancel_remove_list')]
        );

        ctx.reply(
            `👥 Students in ${subject}:\n\n` +
            `Select a student to remove:`,
            Markup.inlineKeyboard(studentButtons)
        );

    } catch (error) {
        console.error('Error selecting subject:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle student selection for removal
removeStudentByListScene.action(/^remove_student_(.+)_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        if (!studentRelation) {
            ctx.reply('❌ Student not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Ask for confirmation
        ctx.reply(
            `⚠️ *Confirm Removal*\n\n` +
            `Are you sure you want to remove ${studentRelation.studentName} (${studentId}) ` +
            `from your ${subject} class?\n\n` +
            `*This will only remove them from your database, not from the school system.*`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Remove', `confirm_list_remove_${studentId}_${subject.replace(/ /g, '_')}`)],
                [Markup.button.callback('❌ No, Cancel', 'cancel_remove_list')]
            ])
        );

    } catch (error) {
        console.error('Error selecting student:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle confirmation for list removal
removeStudentByListScene.action(/^confirm_list_remove_(.+)_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Remove the student
        const result = await TeacherStudent.deleteOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        if (result.deletedCount > 0) {
            ctx.reply(
                `✅ Successfully removed student from your ${subject} class.`,
                teacherMenu
            );
        } else {
            ctx.reply('❌ Student not found or already removed.', teacherMenu);
        }

    } catch (error) {
        console.error('Error removing student:', error);
        ctx.reply('❌ An error occurred while removing the student.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Handle back to subjects
removeStudentByListScene.action('back_to_subjects_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter(); // Go back to subject selection
});

// Handle cancellation
removeStudentByListScene.action('cancel_remove_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Student removal cancelled.', teacherMenu);
    ctx.scene.leave();
});
// Register the scenes
stage.register(teacherRemoveStudentScene);
stage.register(removeStudentByIdScene);
stage.register(removeStudentByListScene);
// Announce Class Scene
const announceClassScene = new Scenes.BaseScene('announce_class_scene');

announceClassScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `announce_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add cancel button
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_announcement')]);

        ctx.reply('📚 Select the subject to announce to:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in announce class scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
announceClassScene.action(/^announce_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this subject
        const studentRelations = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        });

        if (studentRelations.length === 0) {
            ctx.reply(`❌ No students found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Get unique parent IDs
        const studentIds = studentRelations.map(rel => rel.studentId);
        const students = await Student.find({ studentId: { $in: studentIds } });
        const parentIds = [...new Set(students.map(s => s.parentId).filter(id => id !== null))];

        if (parentIds.length === 0) {
            ctx.reply(`❌ No parents found for students in ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Store announcement data in session
        ctx.session.announcementData = {
            subject: subject,
            parentIds: parentIds,
            studentCount: studentRelations.length,
            parentCount: parentIds.length
        };

        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel Announcement']
        ]).resize();

        ctx.reply(
            `📢 Ready to announce to ${subject} class!\n\n` +
            `• Students: ${studentRelations.length}\n` +
            `• Parents: ${parentIds.length}\n\n` +
            `Please send your announcement (text, photo, video, document, audio, or voice):`,
            cancelKeyboard
        );

    } catch (error) {
        console.error('Error selecting subject for announcement:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle all message types for announcement
announceClassScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
    const announcementData = ctx.session.announcementData;
    
    if (!announcementData) {
        ctx.reply('❌ No subject selected. Please start over.', teacherMenu);
        return ctx.scene.leave();
    }

    const { subject, parentIds, studentCount, parentCount } = announcementData;
    const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
    const teacherName = teacher?.name || 'Teacher';

    let successCount = 0;
    let failedCount = 0;
    const failedParents = [];

    try {
        // Send announcement to each parent
        for (const parentId of parentIds) {
            try {
                if (ctx.message.text) {
                    // Text message
                    await ctx.telegram.sendMessage(
                        parentId,
                        `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.text}`,
                        { parse_mode: "HTML" }
                    );
                    successCount++;
                } 
                else if (ctx.message.photo) {
                    // Photo with optional caption
                    const photo = ctx.message.photo[ctx.message.photo.length - 1];
                    const caption = ctx.message.caption 
                        ? `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.caption}`
                        : `📢 Announcement from ${teacherName} (${subject})`;
                    
                    await ctx.telegram.sendPhoto(
                        parentId,
                        photo.file_id,
                        { caption, parse_mode: "HTML" }
                    );
                    successCount++;
                }
                else if (ctx.message.video) {
                    // Video with optional caption
                    const caption = ctx.message.caption 
                        ? `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.caption}`
                        : `📢 Announcement from ${teacherName} (${subject})`;
                    
                    await ctx.telegram.sendVideo(
                        parentId,
                        ctx.message.video.file_id,
                        { caption, parse_mode: "HTML" }
                    );
                    successCount++;
                }
                else if (ctx.message.document) {
                    // Document with optional caption
                    const caption = ctx.message.caption 
                        ? `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.caption}`
                        : `📢 Announcement from ${teacherName} (${subject})`;
                    
                    await ctx.telegram.sendDocument(
                        parentId,
                        ctx.message.document.file_id,
                        { caption, parse_mode: "HTML" }
                    );
                    successCount++;
                }
                else if (ctx.message.audio) {
                    // Audio with optional caption
                    const caption = ctx.message.caption 
                        ? `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.caption}`
                        : `📢 Announcement from ${teacherName} (${subject})`;
                    
                    await ctx.telegram.sendAudio(
                        parentId,
                        ctx.message.audio.file_id,
                        { caption, parse_mode: "HTML" }
                    );
                    successCount++;
                }
                else if (ctx.message.voice) {
                    // Voice message with announcement header
                    await ctx.telegram.sendVoice(
                        parentId,
                        ctx.message.voice.file_id
                    );
                    await ctx.telegram.sendMessage(
                        parentId,
                        `🗣️ *Voice announcement from ${teacherName} (${subject})*`,
                        { parse_mode: "HTML" }
                    );
                    successCount++;
                }
            } catch (error) {
                if (error.response?.error_code === 403) {
                    // Parent blocked the bot
                    failedCount++;
                    failedParents.push(parentId);
                } else {
                    console.error(`Failed to send to parent ${parentId}:`, error);
                    failedCount++;
                    failedParents.push(parentId);
                }
            }
        }

        // Send summary to teacher
        let summaryMessage = `✅ Announcement sent!\n\n`;
        summaryMessage += `📚 Subject: ${subject}\n`;
        summaryMessage += `👥 Students: ${studentCount}\n`;
        summaryMessage += `👨‍👩‍👧‍👦 Parents: ${parentCount}\n`;
        summaryMessage += `✅ Successful: ${successCount}\n`;
        
        if (failedCount > 0) {
            summaryMessage += `❌ Failed: ${failedCount}\n`;
            if (failedParents.length > 0) {
                summaryMessage += `\nFailed to send to ${failedCount} parent(s).`;
            }
        }

        ctx.reply(summaryMessage, teacherMenu);

    } catch (error) {
        console.error('Error sending announcement:', error);
        ctx.reply('❌ An error occurred while sending the announcement.', teacherMenu);
    }

    // Clean up session
    delete ctx.session.announcementData;
    ctx.scene.leave();
});

// Handle cancellation
announceClassScene.action('cancel_announcement', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Announcement cancelled.', teacherMenu);
    delete ctx.session.announcementData;
    ctx.scene.leave();
});

// Handle text cancellation
announceClassScene.hears('❌ Cancel Announcement', async (ctx) => {
    ctx.reply('❌ Announcement cancelled.', teacherMenu);
    delete ctx.session.announcementData;
    ctx.scene.leave();
});

// Handle unsupported media types
announceClassScene.on('message', (ctx) => {
    ctx.reply('❌ Unsupported message type. Please send text, photo, video, document, audio, or voice.');
});
// Register the scene
stage.register(announceClassScene);


// Teacher Add Student Scene
const teacherAddStudentScene = new Scenes.BaseScene('teacher_add_student_scene');

teacherAddStudentScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned. Please add subjects first.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create a keyboard with cancel option
        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel']
        ]).resize();

        ctx.reply('🆔 Please enter the Student ID you want to add to your class:', cancelKeyboard);
    } catch (error) {
        console.error('Error in teacher add student scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

teacherAddStudentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    
    if (studentId === '❌ Cancel') {
        ctx.reply('❌ Student addition cancelled.', teacherMenu);
        return ctx.scene.leave();
    }

    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a valid student ID (e.g., ST1234).');
        return;
    }

    try {
        const student = await getStudentById(studentId);
        if (!student) {
            ctx.reply('❌ Student not found. Please check the Student ID and try again.');
            return;
        }

        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Store student info in session
        ctx.session.studentToAdd = {
            studentId: student.studentId,
            studentName: student.name,
            className: student.class
        };

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `add_to_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add "All Subjects" option and cancel button
        subjectButtons.push(
            [Markup.button.callback('📚 All Subjects', 'add_to_all_subjects')],
            [Markup.button.callback('❌ Cancel', 'cancel_add_student')]
        );

        ctx.reply(
            `👤 Student: ${student.name} (${studentId})\n🏫 Class: ${student.class}\n\n` +
            `Select which subject(s) to add this student to:`,
            Markup.inlineKeyboard(subjectButtons)
        );

    } catch (error) {
        console.error('Error processing student ID:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
teacherAddStudentScene.action(/^add_to_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, className } = ctx.session.studentToAdd;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        // Check if relationship already exists
        const existingRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        if (existingRelation) {
            ctx.reply(`❌ Student ${studentName} is already in your ${subject} class.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Store selected subject and ask for confirmation
        ctx.session.selectedSubject = subject;
        
        ctx.reply(
            `📝 Confirm adding student:\n\n` +
            `👤 Student: ${studentName}\n` +
            `🆔 ID: ${studentId}\n` +
            `🏫 Class: ${className}\n` +
            `📚 Subject: ${subject}\n\n` +
            `Are you sure you want to add this student to your class?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Add Student', 'confirm_add_student')],
                [Markup.button.callback('❌ No, Cancel', 'cancel_add_student')]
            ])
        );

    } catch (error) {
        console.error('Error selecting subject:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle "All Subjects" selection
teacherAddStudentScene.action('add_to_all_subjects', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, className } = ctx.session.studentToAdd;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        // Check which subjects the student is already in
        const existingRelations = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        const existingSubjects = existingRelations.map(rel => rel.subject);
        const subjectsToAdd = teacher.subjects.filter(subject => !existingSubjects.includes(subject));

        if (subjectsToAdd.length === 0) {
            ctx.reply(`❌ Student ${studentName} is already in all your subjects.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Store subjects to add and ask for confirmation
        ctx.session.subjectsToAdd = subjectsToAdd;
        
        ctx.reply(
            `📝 Confirm adding student to all subjects:\n\n` +
            `👤 Student: ${studentName}\n` +
            `🆔 ID: ${studentId}\n` +
            `🏫 Class: ${className}\n` +
            `📚 Subjects: ${subjectsToAdd.join(', ')}\n\n` +
            `Are you sure you want to add this student to all these subjects?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Add to All', 'confirm_add_all_subjects')],
                [Markup.button.callback('❌ No, Cancel', 'cancel_add_student')]
            ])
        );

    } catch (error) {
        console.error('Error selecting all subjects:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle single subject confirmation
teacherAddStudentScene.action('confirm_add_student', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, className } = ctx.session.studentToAdd;
        const subject = ctx.session.selectedSubject;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        // Create the teacher-student relationship
        const newRelation = new TeacherStudent({
            teacherId: teacher.teacherId,
            teacherName: teacher.name,
            studentId: studentId,
            studentName: studentName,
            subject: subject,
            className: className
        });

        await newRelation.save();

        ctx.reply(
            `✅ Successfully added ${studentName} to your ${subject} class!`,
            teacherMenu
        );

    } catch (error) {
        console.error('Error adding student:', error);
        ctx.reply('❌ An error occurred while adding the student.', teacherMenu);
    }
    
    // Clean up session
    delete ctx.session.studentToAdd;
    delete ctx.session.selectedSubject;
    ctx.scene.leave();
});

// Handle all subjects confirmation
teacherAddStudentScene.action('confirm_add_all_subjects', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, className } = ctx.session.studentToAdd;
        const subjects = ctx.session.subjectsToAdd;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        let addedCount = 0;
        const addedSubjects = [];

        for (const subject of subjects) {
            try {
                const newRelation = new TeacherStudent({
                    teacherId: teacher.teacherId,
                    teacherName: teacher.name,
                    studentId: studentId,
                    studentName: studentName,
                    subject: subject,
                    className: className
                });

                await newRelation.save();
                addedCount++;
                addedSubjects.push(subject);
            } catch (error) {
                if (error.code !== 11000) { // Ignore duplicate key errors
                    console.error(`Error adding student to ${subject}:`, error);
                }
            }
        }

        if (addedCount > 0) {
            ctx.reply(
                `✅ Successfully added ${studentName} to ${addedCount} subject(s):\n` +
                `${addedSubjects.join(', ')}`,
                teacherMenu
            );
        } else {
            ctx.reply(
                `❌ Could not add ${studentName} to any subjects. They may already be in all your classes.`,
                teacherMenu
            );
        }

    } catch (error) {
        console.error('Error adding student to all subjects:', error);
        ctx.reply('❌ An error occurred while adding the student.', teacherMenu);
    }
    
    // Clean up session
    delete ctx.session.studentToAdd;
    delete ctx.session.subjectsToAdd;
    ctx.scene.leave();
});

// Handle cancellation from inline buttons
teacherAddStudentScene.action('cancel_add_student', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Student addition cancelled.', teacherMenu);
    
    // Clean up session
    delete ctx.session.studentToAdd;
    delete ctx.session.selectedSubject;
    delete ctx.session.subjectsToAdd;
    
    ctx.scene.leave();
});

// Handle cancellation from text input
teacherAddStudentScene.hears('❌ Cancel', async (ctx) => {
    ctx.reply('❌ Student addition cancelled.', teacherMenu);
    
    // Clean up session
    delete ctx.session.studentToAdd;
    delete ctx.session.selectedSubject;
    delete ctx.session.subjectsToAdd;
    
    ctx.scene.leave();
});

// Register the scene
stage.register(teacherAddStudentScene);
// 
// Manage Grades Main Scene
const manageGradesScene = new Scenes.BaseScene('manage_grades_scene');

manageGradesScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned. Please add subjects first.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `manage_grades_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_manage_grades')]);
        
        ctx.reply('📚 Select a subject to manage grades:', 
            Markup.inlineKeyboard(subjectButtons));
    } catch (error) {
        console.error('Error in manage grades scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});
// Action handler for selecting a subject
manageGradesScene.action(/select_subject_(.+)/, async (ctx) => {
    try {
        // ✅ The key fix: Answer the callback query immediately, and wrap it
        // in a try...catch to handle rapid clicks without crashing.
        await ctx.answerCbQuery(`Selected: ${ctx.match[1]}`);
    } catch (error) {
        // Log the error but don't crash the bot
        console.error('Error answering callback query:', error);
    }
    
    // Now, perform the rest of the logic
    const subject = ctx.match[1];
    ctx.session.selectedGradeSubject = subject;
    ctx.session.page = 0;
    ctx.session.state = 'selecting_student';
    await showStudentList(ctx);
});
// Handle subject selection
manageGradesScene.action(/^manage_grades_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const students = await getStudentsByTeacherAndSubject(teacher.teacherId, subject);
        
        if (students.length === 0) {
            ctx.reply(`❌ No students found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }
        
        // Store subject in session
        ctx.session.gradeSubject = subject;
        
        // Create student buttons (sorted alphabetically)
        const studentButtons = students.map(student => 
            [Markup.button.callback(
                `${student.studentName} (${student.studentId})`, 
                `manage_grades_student_${student.studentId}`
            )]
        );
        
        // Add back and cancel buttons
        studentButtons.push(
            [Markup.button.callback('⬅️ Back to Subjects', 'back_to_grade_subjects')],
            [Markup.button.callback('❌ Cancel', 'cancel_manage_grades')]
        );
        
        ctx.reply(`👥 Students in ${subject}:`, Markup.inlineKeyboard(studentButtons));
    } catch (error) {
        console.error('Error selecting subject for grades:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle student selection
manageGradesScene.action(/^manage_grades_student_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const student = await getStudentById(studentId);
        const subject = ctx.session.gradeSubject;
        
        if (!student) {
            ctx.reply('❌ Student not found.', teacherMenu);
            return ctx.scene.leave();
        }
        
        // Store student info in session
        ctx.session.gradeStudentId = studentId;
        ctx.session.gradeStudentName = student.name;
        
        // Get existing grades for this student and subject
        const grades = await getStudentGrades(studentId, subject);
        
        let message = `📊 *Grades for ${student.name} in ${subject}:*\n\n`;
        
        if (grades.length === 0) {
            message += 'No grades recorded yet.\n';
        } else {
            // Calculate average
            const total = grades.reduce((sum, grade) => sum + grade.score, 0);
            const average = total / grades.length;
            
            message += `📈 Average: ${average.toFixed(2)}%\n\n`;
            
            grades.forEach((grade, index) => {
                message += `${index + 1}. ${grade.purpose}: ${grade.score}% (${new Date(grade.date).toLocaleDateString()})\n`;
                if (grade.comments) {
                    message += `   💬 ${grade.comments}\n`;
                }
            });
        }
        
        // Create action buttons
        // Add the Remove Grade button here
const actionButtons = [
  [Markup.button.callback('➕ Add Grade', 'add_grade')],
  [Markup.button.callback('📝 Edit Grades', 'edit_grades')],
  [Markup.button.callback('🗑️ Remove Grade', 'remove_grades')],    // <-- Add this line
  [Markup.button.callback('⬅️ Back to Students', 'back_to_grade_students')],
  [Markup.button.callback('❌ Cancel', 'cancel_manage_grades')]
];

        
        ctx.replyWithHTML(message, Markup.inlineKeyboard(actionButtons));
    } catch (error) {
        console.error('Error selecting student for grades:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle add grade action
manageGradesScene.action('add_grade', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('add_grade_scene');
});
manageGradesScene.action('remove_grades', async (ctx) => {
  await ctx.answerCbQuery();
  // Enter a scene or implement remove grade functionality here
  ctx.scene.enter('remove_grade_scene');
});
manageGradesScene.action('edit_grades', async (ctx) => {await ctx.answerCbQuery()
ctx.scene.enter('edit_grades_scene');});

// Handle back to students
manageGradesScene.action('back_to_grade_students', async (ctx) => {
    await ctx.answerCbQuery();
    // Re-enter the scene to show students again
    const subject = ctx.session.gradeSubject;
    ctx.scene.enter('manage_grades_scene');
    
    
});

// Handle back to subjects
manageGradesScene.action('back_to_grade_subjects', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter();
});

// Handle cancel
manageGradesScene.action('cancel_manage_grades', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Grade management cancelled.', teacherMenu);
    ctx.scene.leave();
});

// --- Stepwise Add Grade Scene ---

const addGradeScene = new Scenes.BaseScene('add_grade_scene');

addGradeScene.enter((ctx) => {
  ctx.session.newGrade = {}; // Initialize grade container
  ctx.reply('📝 Adding a new grade.\nPlease enter the *score* (0-100). Type ❌ Cancel to abort.', { parse_mode: "HTML" });
});

// Step 1: Score input
addGradeScene.on('text', async (ctx) => {
  const text = ctx.message.text.trim();
  if (text === '❌ Cancel') {
    ctx.reply('❌ Grade addition cancelled.', teacherMenu);
    ctx.scene.leave();
    return;
  }

  if (!ctx.session.newGrade.score) {
    const score = parseInt(text);
    if (isNaN(score) || score < 0 || score > 100) {
      return ctx.reply('❌ Invalid score. Please enter a number between 0 and 100.');
    }
    ctx.session.newGrade.score = score;
    return ctx.reply('Please enter the purpose of this grade (e.g., quiz, test, homework, or any descriptive term).', { parse_mode: "HTML" });
  }

  // Step 2: Purpose input
  if (!ctx.session.newGrade.purpose) {
    if (!text || text.length > 100) { // Basic validation: non-empty, max 100 characters
      return ctx.reply('❌ Invalid purpose. Please enter a non-empty purpose (max 100 characters).');
    }
    ctx.session.newGrade.purpose = text; // Accept any purpose
    return ctx.reply('Optional: Enter comments or type "skip" to omit.', { parse_mode: "HTML" });
  }

  // Step 3: Comments input (optional)
  if (ctx.session.newGrade.comments === undefined) {
    let comments = text;
    if (comments.toLowerCase() === 'skip') comments = '';
    if (comments.length > 500) { // Limit comments to 500 characters
      return ctx.reply('❌ Comments cannot exceed 500 characters.');
    }
    ctx.session.newGrade.comments = comments;

    // Save the grade
    try {
      const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
      const studentId = ctx.session.gradeStudentId;
      const studentName = ctx.session.gradeStudentName;
      const subject = ctx.session.gradeSubject;
      const { score, purpose, comments } = ctx.session.newGrade;
      const gradeId = await generateUniqueGradeId();

      const newGrade = new Grade({
        gradeId,
        studentId,
        studentName,
        teacherId: teacher.teacherId,
        teacherName: teacher.name,
        subject,
        score,
        purpose, // Store custom purpose
        comments,
        date: new Date()
      });
      await newGrade.save();
      
      ctx.replyWithHTML(
        `✅ Grade added successfully!\n\n` +
        `*Student:* ${studentName}\n` +
        `*Subject:* ${subject}\n` +
        `*Score:* ${score}%\n` +
        `*Purpose:* ${purpose}\n` +
        `${comments ? `*Comments:* ${comments}\n` : ''}`,
        teacherMenu
      );
    } catch (error) {
      console.error('Error adding grade:', error);
      ctx.reply('❌ An error occurred while adding the grade.', teacherMenu);
    }
    // Clean up session
    delete ctx.session.newGrade;
    ctx.scene.leave();
  }
});

// --- Remove Grade Scene ---

const removeGradeScene = new Scenes.BaseScene('remove_grade_scene');

removeGradeScene.enter(async (ctx) => {
  try {
    const studentId = ctx.session.gradeStudentId;
    const subject = ctx.session.gradeSubject;
    const grades = await getStudentGrades(studentId, subject);

    if (grades.length === 0) {
      ctx.reply('❌ No grades found to remove.', teacherMenu);
      return ctx.scene.leave();
    }

    const buttons = grades.map(g => 
      [Markup.button.callback(
        `${g.purpose}: ${g.score}% (${new Date(g.date).toLocaleDateString()})`,
        `remove_grade_${g.gradeId}`)]
    );
    buttons.push([Markup.button.callback('⬅️ Cancel', 'cancel_remove_grade')]);

    ctx.replyWithHTML(`🗑️ Select a grade to remove for *${ctx.session.gradeStudentName}* in *${subject}:*`, Markup.inlineKeyboard(buttons));
  } catch (error) {
    console.error('Error entering remove grade scene:', error);
    ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
    ctx.scene.leave();
  }
});

// Handle grade removal action
removeGradeScene.action(/^remove_grade_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const gradeId = ctx.match[1];
  try {
    const grade = await Grade.findOne({ gradeId });
    if (!grade) {
      ctx.reply('❌ Grade not found.', teacherMenu);
      return ctx.scene.leave();
    }

    await Grade.deleteOne({ gradeId });
    ctx.replyWithHTML(`✅ Grade for *${grade.purpose}* (${grade.score}%) removed successfully.`, teacherMenu);
    ctx.scene.leave();
  } catch (error) {
    console.error('Error removing grade:', error);
    ctx.reply('❌ An error occurred while removing the grade.', teacherMenu);
    ctx.scene.leave();
  }
});

// Cancel handler
removeGradeScene.action('cancel_remove_grade', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.reply('❌ Grade removal cancelled.', teacherMenu);
  ctx.scene.leave();
});

/// --- Enhanced Edit Grades Scene: Stepwise Editing ---

const editGradesScene = new Scenes.BaseScene('edit_grades_scene');
const editGradeProcessScene = new Scenes.BaseScene('edit_grade_process_scene');

editGradesScene.enter(async (ctx) => {
  try {
    const studentId = ctx.session.gradeStudentId;
    const subject = ctx.session.gradeSubject;
    const studentName = ctx.session.gradeStudentName;
    const grades = await getStudentGrades(studentId, subject);

    if (grades.length === 0) {
      ctx.reply('❌ No grades found to edit.', teacherMenu);
      return ctx.scene.leave();
    }

    const gradeButtons = grades.map(grade =>
      [Markup.button.callback(
        `${grade.purpose}: ${grade.score}% (${new Date(grade.date).toLocaleDateString()})`,
        `edit_grade_${grade.gradeId}`
      )]
    );
    gradeButtons.push(
      [Markup.button.callback('⬅️ Back', 'back_to_grade_management')],
      [Markup.button.callback('❌ Cancel', 'cancel_edit_grades')]
    );

    ctx.replyWithHTML(
      `📝 Select a grade to edit for *${studentName}* in *${subject}:*\n` +
      `Note: You can set any purpose for the grade during editing.`,
      Markup.inlineKeyboard(gradeButtons)
    );
  } catch (error) {
    console.error('Error in edit grades scene:', error);
    ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
    ctx.scene.leave();
  }
});

editGradesScene.action(/^edit_grade_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const gradeId = ctx.match[1];
  try {
    const grade = await Grade.findOne({ gradeId });
    if (!grade) {
      ctx.reply('❌ Grade not found.', teacherMenu);
      return ctx.scene.leave();
    }
    // Store current grade in session for editing
    ctx.session.editingGrade = {
      gradeId: grade.gradeId,
      score: grade.score,
      purpose: grade.purpose,
      comments: grade.comments || ''
    };
    ctx.reply(`📝 Current score: ${grade.score}\nPlease enter the new score (0-100). Type ❌ Cancel to abort.`);
    ctx.scene.enter('edit_grade_process_scene');
  } catch (error) {
    console.error('Error selecting grade for editing:', error);
    ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
    ctx.scene.leave();
  }
});

// Handle back to grade management
editGradesScene.action('back_to_grade_management', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.scene.enter('manage_grades_scene');
});

// Handle cancel
editGradesScene.action('cancel_edit_grades', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.reply('❌ Grade editing cancelled.', teacherMenu);
  ctx.scene.leave();
});

// --- Edit Grade Process Scene ---
editGradeProcessScene.enter((ctx) => {
  // This scene handles the step-by-step editing process
  ctx.reply('📝 Please enter the new score (0-100). Type ❌ Cancel to abort.');
});

editGradeProcessScene.on('text', async (ctx) => {
  const text = ctx.message.text.trim();
  
  if (text === '❌ Cancel') {
    // Clean up session
    delete ctx.session.newScore;
    delete ctx.session.newPurpose;
    delete ctx.session.newComments;
    delete ctx.session.editingGrade;
    ctx.reply('❌ Grade editing cancelled.', teacherMenu);
    return ctx.scene.leave();
  }

  // Step 1: Score input
  if (!ctx.session.newScore) {
    const score = parseInt(text);
    if (isNaN(score) || score < 0 || score > 100) {
      return ctx.reply('❌ Invalid score. Please enter a number between 0 and 100.');
    }
    ctx.session.newScore = score;
    return ctx.reply('Please enter the purpose of this grade (e.g., quiz, test, homework, or any descriptive term).');
  }

  // Step 2: Purpose input
  if (!ctx.session.newPurpose) {
    if (!text || text.length > 100) { // Basic validation: non-empty, max 100 characters
      return ctx.reply('❌ Invalid purpose. Please enter a non-empty purpose (max 100 characters).');
    }
    ctx.session.newPurpose = text; // Accept any purpose
    return ctx.reply('Optional: Enter comments or type "skip" to omit.');
  }

  // Step 3: Comments input (optional)
  if (ctx.session.newComments === undefined) {
    let comments = text;
    if (comments.toLowerCase() === 'skip') comments = '';
    if (comments.length > 500) {
      return ctx.reply('❌ Comments cannot exceed 500 characters.');
    }
    ctx.session.newComments = comments;

    // Save the updated grade
    try {
      const { gradeId } = ctx.session.editingGrade;
      const { newScore, newPurpose, newComments } = ctx.session;

      const grade = await Grade.findOne({ gradeId });
      if (!grade) {
        ctx.reply('❌ Grade not found.', teacherMenu);
        return ctx.scene.leave();
      }

      grade.score = newScore;
      grade.purpose = newPurpose; // Store custom purpose
      grade.comments = newComments;
      grade.date = new Date();
      await grade.save();

      ctx.replyWithHTML(
        `✅ Grade updated successfully!\n\n` +
        `*Student:* ${grade.studentName}\n` +
        `*Subject:* ${grade.subject}\n` +
        `*Score:* ${newScore}%\n` +
        `*Purpose:* ${newPurpose}\n` +
        `${newComments ? `*Comments:* ${newComments}\n` : ''}`,
        teacherMenu
      );
    } catch (error) {
      console.error('Error updating grade:', error);
      ctx.reply('❌ An error occurred while updating the grade.', teacherMenu);
    }

    // Clean up session
    delete ctx.session.newScore;
    delete ctx.session.newPurpose;
    delete ctx.session.newComments;
    delete ctx.session.editingGrade;
    
    ctx.scene.leave();
  }
});

// Handle cancel in process scene
editGradeProcessScene.hears('❌ Cancel', async (ctx) => {
  // Clean up session
  delete ctx.session.newScore;
  delete ctx.session.newPurpose;
  delete ctx.session.newComments;
  delete ctx.session.editingGrade;
  
  ctx.reply('❌ Grade editing cancelled.', teacherMenu);
  ctx.scene.leave();
});

// Register the scenes
stage.register(editGradesScene);
stage.register(editGradeProcessScene);
stage.register(manageGradesScene);
stage.register(addGradeScene);
stage.register(removeGradeScene);
stage.register(editGradesScene);
stage.register(editGradeProcessScene);



// Teacher Upload Student List Scene

// Contact Admins Scene
const contactAdminsScene = new Scenes.BaseScene('contact_admins_scene');

contactAdminsScene.enter(async (ctx) => {
    try {
        // Get all admins except the current user
        const admins = await User.find({ role: 'admin' });
        const filteredAdmins = admins.filter(admin => admin.telegramId !== ctx.from.id.toString());
        
        if (filteredAdmins.length === 0) {
            ctx.reply('❌ No other admins found to contact.', adminMenu);
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each admin
        const adminButtons = filteredAdmins.map(admin => 
            [Markup.button.callback(
                `${admin.name} (ID: ${admin.telegramId})`, 
                `select_admin_${admin.telegramId}`
            )]
        );
        
        // Add cancel button
        adminButtons.push([Markup.button.callback('❌ Cancel', 'cancel_contact_admins')]);
        
        ctx.reply('👑 Select an admin to contact:', Markup.inlineKeyboard(adminButtons));
    } catch (error) {
        console.error('Error retrieving admins:', error);
        ctx.reply('❌ An error occurred while retrieving admins.', adminMenu);
        ctx.scene.leave();
    }
});

// Handle admin selection
contactAdminsScene.action(/^select_admin_(\d+)$/, async (ctx) => {
    const adminTelegramId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const admin = await getUserById(adminTelegramId);
        if (!admin) {
            ctx.reply('❌ Admin not found.', adminMenu);
            return ctx.scene.leave();
        }
        
        // Store recipient info in session
        ctx.session.recipientId = adminTelegramId;
        ctx.session.recipientName = admin.name;
        
        ctx.reply(`📬 You are now messaging **${admin.name}** (ID: ${adminTelegramId}).\n📤 Send any message (text, photo, video, document, audio, voice).`, Markup.keyboard([['❌ Cancel']]).resize());
        ctx.scene.enter('send_message_to_admin_scene');
    } catch (error) {
        console.error('Error selecting admin:', error);
        ctx.reply('❌ An error occurred.', adminMenu);
        ctx.scene.leave();
    }
});

// Handle cancel action
contactAdminsScene.action('cancel_contact_admins', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Contact admins cancelled.', adminMenu);
    ctx.scene.leave();
});
/// Admin-only: Contact Parent by Telegram ID
const contactParentAdminScene = new Scenes.BaseScene('contact_parent_admin_scene');

contactParentAdminScene.enter((ctx) => {
  const cancelKeyboard = Markup.keyboard([
    ['❌ Cancel']
  ]).resize();

  ctx.reply(
    '🆔 Please enter the *Telegram ID* of the parent you want to contact.\n\n' +
    '🔍 Tip: Use /search to find parents by name if you don’t know the ID.',
    cancelKeyboard
  );
});

// Handle Cancel
contactParentAdminScene.hears('❌ Cancel', async (ctx) => {
  ctx.session.recipientId = null;
  ctx.session.recipientName = null;
  await ctx.reply('❌ Operation cancelled.', adminMenu);
  return ctx.scene.leave();
});

// Handle Parent ID input
contactParentAdminScene.on('text', async (ctx) => {
  const input = ctx.message.text.trim();

  if (input === '❌ Cancel') {
    return ctx.scene.reenter(); // Triggers the cancel handler
  }

  // Validate numeric ID
  if (!/^\d+$/.test(input)) {
    return ctx.reply(
      '❌ Invalid Telegram ID. Please enter a numeric ID.\n\n' +
      '💡 Use /search to look up parents by name.'
    );
  }

  const parentId = parseInt(input, 10);

  try {
    const parent = await getUserById(parentId);
    if (!parent || parent.role !== 'parent') {
      return ctx.reply(
        '❌ No parent found with that ID.\n\n' +
        '💡 Try using /search to find the parent by name.'
      );
    }

    // Store recipient
    ctx.session.recipientId = parentId;
    ctx.session.recipientName = parent.name;

    const replyKeyboard = Markup.keyboard([
      ['❌ Cancel']
    ]).resize();

    ctx.reply(
      `📬 You are now messaging **${parent.name}** (ID: ${parentId}).\n` +
      '📤 Send any message (text, photo, video, document, audio, voice).',
      replyKeyboard
    );
    ctx.scene.enter('send_message_to_parent_admin_scene');
  } catch (error) {
    console.error('Error finding parent by ID:', error);
    ctx.reply('❌ An error occurred while retrieving the parent.');
  }
});

// Send Message to Admin Scene
const sendMessageToAdminScene = new Scenes.BaseScene('send_message_to_admin_scene');

// Handle Cancel
sendMessageToAdminScene.hears('❌ Cancel', async (ctx) => {
    ctx.session.recipientId = null;
    ctx.session.recipientName = null;
    await ctx.reply('❌ Message cancelled.', adminMenu);
    return ctx.scene.leave();
});

// Handle all message types
sendMessageToAdminScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
    const recipientId = ctx.session.recipientId;
    if (!recipientId) {
        await ctx.reply('❌ Recipient not set. Starting over.', adminMenu);
        return ctx.scene.leave();
    }

    const senderName = ctx.from.first_name || ctx.from.username || 'Admin';

    try {
        if (ctx.message.text) {
            const text = ctx.message.text.trim();
            await ctx.telegram.sendMessage(
                recipientId,
                `📢 *Message from Admin ${senderName}:*\n${text}`,
                { parse_mode: "HTML" }
            );
        } 
        else if (ctx.message.photo) {
            const photo = ctx.message.photo[ctx.message.photo.length - 1];
            const caption = ctx.message.caption
                ? `📢 *Message from Admin ${senderName}:*\n${ctx.message.caption}`
                : `📢 Message from Admin ${senderName}`;
            await ctx.telegram.sendPhoto(recipientId, photo.file_id, {
                caption,
                parse_mode: "HTML"
            });
        } 
        else if (ctx.message.video) {
            const caption = ctx.message.caption
                ? `📢 *Message from Admin ${senderName}:*\n${ctx.message.caption}`
                : `📢 Message from Admin ${senderName}`;
            await ctx.telegram.sendVideo(recipientId, ctx.message.video.file_id, {
                caption,
                parse_mode: "HTML"
            });
        } 
        else if (ctx.message.document) {
            const caption = ctx.message.caption
                ? `📢 *Message from Admin ${senderName}:*\n${ctx.message.caption}`
                : `📢 Message from Admin ${senderName}`;
            await ctx.telegram.sendDocument(recipientId, ctx.message.document.file_id, {
                caption,
                parse_mode: "HTML"
            });
        } 
        else if (ctx.message.audio) {
            const caption = ctx.message.caption
                ? `📢 *Message from Admin ${senderName}:*\n${ctx.message.caption}`
                : `📢 Message from Admin ${senderName}`;
            await ctx.telegram.sendAudio(recipientId, ctx.message.audio.file_id, {
                caption,
                parse_mode: "HTML"
            });
        } 
        else if (ctx.message.voice) {
            await ctx.telegram.sendVoice(recipientId, ctx.message.voice.file_id);
            await ctx.telegram.sendMessage(
                recipientId,
                `🗨️ *Voice message from Admin ${senderName}*`,
                { parse_mode: "HTML" }
            );
        }

        await ctx.reply('✅ Message sent successfully!', adminMenu);
    } catch (error) {
        if (error.response?.error_code === 403) {
            await ctx.reply(
                '❌ Failed to send message. The admin may have blocked the bot.',
                adminMenu
            );
        } else {
            console.error('Error sending message to admin:', error);
            await ctx.reply('❌ Failed to send message. Please try again later.', adminMenu);
        }
    } finally {
        ctx.session.recipientId = null;
        ctx.session.recipientName = null;
        ctx.scene.leave();
    }
});

// Fallback for unsupported types
sendMessageToAdminScene.on('message', (ctx) => {
    ctx.reply('⚠️ Unsupported content. Please send text, photo, video, document, audio, or voice.');
});
stage.register(contactAdminsScene);
stage.register(sendMessageToAdminScene);

// Send any message/media to parent — includes admin name
const sendMessageToParentAdminScene = new Scenes.BaseScene('send_message_to_parent_admin_scene');

// Handle Cancel
sendMessageToParentAdminScene.hears('❌ Cancel', async (ctx) => {
  ctx.session.recipientId = null;
  ctx.session.recipientName = null;
  await ctx.reply('❌ Message cancelled.', adminMenu);
  return ctx.scene.leave();
});

// Handle all message types
sendMessageToParentAdminScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
  const recipientId = ctx.session.recipientId;
  if (!recipientId) {
    await ctx.reply('❌ Recipient not set. Starting over.', adminMenu);
    return ctx.scene.leave();
  }

  const adminName = ctx.from.first_name || ctx.from.username || 'Admin';

  try {
    if (ctx.message.text) {
      const text = ctx.message.text.trim();
      await ctx.telegram.sendMessage(
        recipientId,
        `📢 *Message from Admin (${adminName}):*\n${text}`,
        { parse_mode: "HTML" }
      );
    } 
    else if (ctx.message.photo) {
      const photo = ctx.message.photo[ctx.message.photo.length - 1];
      const caption = ctx.message.caption
        ? `📢 *Message from Admin (${adminName})*:\n${ctx.message.caption}`
        : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendPhoto(recipientId, photo.file_id, {
        caption,
        parse_mode: "HTML"
      });
    } 
    else if (ctx.message.video) {
      const caption = ctx.message.caption
        ? `📢 *Message from Admin (${adminName})*:\n${ctx.message.caption}`
        : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendVideo(recipientId, ctx.message.video.file_id, {
        caption,
        parse_mode: "HTML"
      });
    } 
    else if (ctx.message.document) {
      const caption = ctx.message.caption
        ? `📢 *Message from Admin (${adminName})*:\n${ctx.message.caption}`
        : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendDocument(recipientId, ctx.message.document.file_id, {
        caption,
        parse_mode: "HTML"
      });
    } 
    else if (ctx.message.audio) {
      const caption = ctx.message.caption
        ? `📢 *Message from Admin (${adminName})*:\n${ctx.message.caption}`
        : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendAudio(recipientId, ctx.message.audio.file_id, {
        caption,
        parse_mode: "HTML"
      });
    } 
    else if (ctx.message.voice) {
      await ctx.telegram.sendVoice(recipientId, ctx.message.voice.file_id);
      await ctx.telegram.sendMessage(
        recipientId,
        `🗨️ *Voice message from Admin (${adminName})*`,
        { parse_mode: "HTML" }
      );
    }

    await ctx.reply('✅ Message sent successfully!', adminMenu);
  } catch (error) {
    if (error.response?.error_code === 403) {
      await ctx.reply(
        '❌ Failed to send message. The parent may have blocked the bot.',
        adminMenu
      );
    } else {
      console.error('Error sending message to parent:', error);
      await ctx.reply('❌ Failed to send message. Please try again later.', adminMenu);
    }
  } finally {
    ctx.session.recipientId = null;
    ctx.session.recipientName = null;
    ctx.scene.leave();
  }
});

// Fallback for unsupported types
sendMessageToParentAdminScene.on('message', (ctx) => {
  ctx.reply('⚠️ Unsupported content. Please send text, photo, video, document, audio, or voice.');
});

stage.register(sendMessageToParentAdminScene);
stage.register(contactParentAdminScene);

// Contact Teacher Scene - Admin picks teacher to contact
const contactTeacherScene = new Scenes.BaseScene('contact_teacher_scene');

contactTeacherScene.enter(async (ctx) => {
  // List all teachers to select
  try {
    const teachers = await Teacher.find().sort({ name: 1 });
    if (teachers.length === 0) {
      ctx.reply('❌ No teachers found.');
      return ctx.scene.leave();
    }
    const teacherButtons = teachers.map((teacher) =>
      [Markup.button.callback(`${teacher.name} (ID: ${teacher.teacherId})`, `select_contact_teacher_${teacher.teacherId}`)]
    );
    teacherButtons.push([Markup.button.callback('❌ Cancel', 'cancel_contact_teacher')]);
    ctx.reply('🧑🏫 Select a teacher to contact:', Markup.inlineKeyboard(teacherButtons));
  } catch (error) {
    console.error('Error fetching teachers in contactTeacherScene:', error);
    ctx.reply('❌ An error occurred. Please try again later.');
    ctx.scene.leave();
  }
});

contactTeacherScene.action(/^select_contact_teacher_(.+)$/, async (ctx) => {
  const teacherId = ctx.match[1];
  await ctx.answerCbQuery();
  ctx.session.contactTeacherId = teacherId;
  ctx.reply('📝 Please send the message or media you want to send to the teacher.');
  ctx.scene.enter('send_contact_teacher_message_scene');
});

contactTeacherScene.action('cancel_contact_teacher', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.reply('❌ Contact cancelled.', adminMenu);
  ctx.scene.leave();
});

// Scene for sending message/media to selected teacher
const sendContactTeacherMessageScene = new Scenes.BaseScene('send_contact_teacher_message_scene');

sendContactTeacherMessageScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
  const teacherId = ctx.session.contactTeacherId;
  if (!teacherId) {
    ctx.reply('❌ No teacher selected. Please start again.');
    return ctx.scene.leave();
  }
  try {
    const teacher = await getTeacherById(teacherId);
    if (!teacher || !teacher.telegramId) {
      ctx.reply('❌ Teacher not found or not linked with Telegram.');
      return ctx.scene.leave();
    }
    const adminName = ctx.from.first_name || ctx.from.username || 'Admin';

    // Determine message content type
    if (ctx.message.text) {
      // Text message
      const textToSend = `📢 *Message from Admin (${adminName}):*\n${ctx.message.text.trim()}`;
      await ctx.telegram.sendMessage(teacher.telegramId, textToSend, { parse_mode: "HTML" });
    } else if (ctx.message.photo) {
      // Photo (send highest resolution)
      const photoArray = ctx.message.photo;
      const highestResPhoto = photoArray[photoArray.length - 1];
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendPhoto(teacher.telegramId, highestResPhoto.file_id, { caption, parse_mode: "HTML" });
    } else if (ctx.message.video) {
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendVideo(teacher.telegramId, ctx.message.video.file_id, { caption, parse_mode: "HTML" });
    } else if (ctx.message.document) {
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendDocument(teacher.telegramId, ctx.message.document.file_id, { caption, parse_mode: "HTML" });
    } else if (ctx.message.audio) {
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendAudio(teacher.telegramId, ctx.message.audio.file_id, { caption, parse_mode: "HTML" });
    } else if (ctx.message.voice) {
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendVoice(teacher.telegramId, ctx.message.voice.file_id, { caption, parse_mode: "HTML" });
    } else {
      ctx.reply('❌ Unsupported message type. Please send text, photo, video, document, audio, or voice.');
      return;
    }
    ctx.reply('✅ Message sent to the teacher.', adminMenu);
  } catch (error) {
    if (error.response && error.response.error_code === 403) {
      ctx.reply('❌ Cannot send message, the teacher may have blocked the bot.');
    } else {
      console.error('Error sending contact teacher message:', error);
      ctx.reply('❌ An error occurred while sending the message.');
    }
  } finally {
    ctx.session.contactTeacherId = null;
    ctx.scene.leave();
  }
});

sendContactTeacherMessageScene.on('message', (ctx) => {
  ctx.reply('❌ Please send a valid message type: text, photo, video, document, audio, or voice.');
});

stage.register(contactTeacherScene);
stage.register(sendContactTeacherMessageScene);

/// Remove Teacher Scene - Enhanced with complete data cleanup including userSchema teacher data
const removeTeacherScene = new Scenes.BaseScene('remove_teacher_scene');

removeTeacherScene.enter(async (ctx) => {
    try {
        // Get all registered teachers
        const teachers = await Teacher.find().sort({ name: 1 });
        
        if (teachers.length === 0) {
            ctx.reply('❌ No teachers found to remove.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each teacher
        const teacherButtons = teachers.map(teacher => 
            [Markup.button.callback(
                `${teacher.name} (ID: ${teacher.teacherId})`, 
                `remove_teacher_${teacher.teacherId}`
            )]
        );
        
        // Add cancel button
        teacherButtons.push([Markup.button.callback('❌ Cancel', 'cancel_remove_teacher')]);
        
        ctx.reply('🧑🏫 Select a teacher to remove:', Markup.inlineKeyboard(teacherButtons));
    } catch (error) {
        console.error('Error retrieving teachers for removal:', error);
        ctx.reply('❌ An error occurred while retrieving teachers.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        ctx.scene.leave();
    }
});

// Handle teacher selection for removal
removeTeacherScene.action(/^remove_teacher_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const teacher = await getTeacherById(teacherId);
        if (!teacher) {
            ctx.reply('❌ Teacher not found.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        // Store teacher info in session for confirmation
        ctx.session.teacherToRemove = teacher;
        
        // Get statistics for confirmation message
        const studentRelationsCount = await TeacherStudent.countDocuments({ teacherId });
        const gradesCount = await Grade.countDocuments({ teacherId });
        
        // Check if teacher has user schema data
        let userSchemaData = 0;
        if (teacher.telegramId) {
            const user = await getUserById(teacher.telegramId);
            if (user) {
                // Count teacher-specific data in user schema
                if (user.role === 'teacher') userSchemaData++;
                if (user.subjects && user.subjects.length > 0) userSchemaData++;
                if (user.adminId !== undefined && user.adminId !== null) userSchemaData++;
            }
        }
        
        // Ask for confirmation with detailed information
        ctx.replyWithHTML(
            `⚠️ *Confirm Teacher Removal*\n\n` +
            `*Teacher Details:*\n` +
            `• Name: ${teacher.name}\n` +
            `• ID: ${teacher.teacherId}\n` +
            `• Subjects: ${teacher.subjects.join(', ') || 'None'}\n` +
            `• Telegram ID: ${teacher.telegramId || 'Not linked'}\n\n` +
            `*Associated Data:*\n` +
            `• Student Relationships: ${studentRelationsCount}\n` +
            `• Grades Assigned: ${gradesCount}\n` +
            `• User Schema Data: ${userSchemaData} fields\n\n` +
            `*This action will permanently delete:*\n` +
            `• Teacher profile\n` +
            `• All student-teacher relationships\n` +
            `• All grades assigned by this teacher\n` +
            `• Teacher login credentials\n` +
            `• Teacher data in user schema\n\n` +
            `*This action cannot be undone!*\n\n` +
            `Are you sure you want to proceed?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Remove Everything', `confirm_remove_${teacherId}`)],
                [Markup.button.callback('❌ No, Cancel', 'cancel_remove_teacher')]
            ])
        );
    } catch (error) {
        console.error('Error in remove teacher scene:', error);
        ctx.reply('❌ An error occurred.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        ctx.scene.leave();
    }
});

// Handle confirmation of removal with complete data cleanup including userSchema
removeTeacherScene.action(/^confirm_remove_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const teacher = await getTeacherById(teacherId);
        if (!teacher) {
            ctx.reply('❌ Teacher not found.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        const teacherName = teacher.name;
        const teacherTelegramId = teacher.telegramId;
        
        // Start transaction-like cleanup process
        let deletedRelations = 0;
        let deletedGrades = 0;
        let userSchemaCleaned = false;
        let userAccountHandled = false;
        
        try {
            // 1. Remove all teacher-student relationships
            const relationsResult = await TeacherStudent.deleteMany({ teacherId });
            deletedRelations = relationsResult.deletedCount;
            
            // 2. Remove all grades assigned by this teacher
            const gradesResult = await Grade.deleteMany({ teacherId });
            deletedGrades = gradesResult.deletedCount;
            
            // 3. Remove teacher login credentials
            await TeacherLogin.deleteOne({ teacherId });
            
            // 4. Remove the teacher record
            await Teacher.deleteOne({ teacherId });
            
            // 5. Clean up user schema data for this teacher
            if (teacherTelegramId) {
                const user = await getUserById(teacherTelegramId);
                if (user) {
                    userAccountHandled = true;
                    
                    // Remove all teacher-specific data from user schema
                    if (user.role === 'teacher') {
                        user.role = 'user'; // Downgrade to regular user
                    }
                    
                    // Clear teacher-specific fields
                    user.subjects = []; // Clear subjects array
                    
                    // Clear adminId if it exists (shouldn't for teachers, but just in case)
                    if (user.adminId !== undefined && user.adminId !== null) {
                        user.adminId = null;
                    }
                    
                    // Clear any other teacher-specific fields that might exist
                    if (user.teacherId !== undefined) {
                        user.teacherId = undefined;
                    }
                    
                    await user.save();
                    userSchemaCleaned = true;
                    
                    // If user has no other purpose, consider deleting completely
                    // (This is optional - keeping the user as 'user' role might be better)
                }
            }
            
            // Send success message with cleanup summary
            ctx.replyWithHTML(
                `✅ *Teacher successfully removed!*\n\n` +
                `🧑🏫 *Teacher:* ${teacherName}\n` +
                `🆔 *ID:* ${teacherId}\n\n` +
                `🗑️ *Data Cleanup Summary:*\n` +
                `• Student relationships removed: ${deletedRelations}\n` +
                `• Grades removed: ${deletedGrades}\n` +
                `• Login credentials removed: ✅\n` +
                `• Teacher profile removed: ✅\n` +
                `• User schema data cleaned: ${userSchemaCleaned ? '✅' : '❌'}\n` +
                `• User account handled: ${userAccountHandled ? '✅' : 'N/A'}\n\n` +
                `*All associated data has been permanently deleted or cleaned.*`,
                {
                    reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
                }
            );
            
        } catch (cleanupError) {
            console.error('Error during teacher data cleanup:', cleanupError);
            ctx.reply(
                `⚠️ *Partial Removal Completed*\n\n` +
                `Teacher ${teacherName} was removed, but some data cleanup failed. ` +
                `Please contact system administrator to verify complete removal.\n\n` +
                `Cleanup status:\n` +
                `• Teacher profile: ✅\n` +
                `• User schema: ${userSchemaCleaned ? '✅' : '❌'}\n` +
                `• Error: ${cleanupError.message}`,
                {
                    reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
                }
            );
        }
        
    } catch (error) {
        console.error('Error removing teacher:', error);
        ctx.reply('❌ An error occurred while removing the teacher.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
    }
    
    // Clean up session
    delete ctx.session.teacherToRemove;
    ctx.scene.leave();
});

// Handle cancellation
removeTeacherScene.action('cancel_remove_teacher', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Teacher removal cancelled.', {
        reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
    });
    
    // Clean up session
    delete ctx.session.teacherToRemove;
    ctx.scene.leave();
});

// Register the scene
stage.register(removeTeacherScene);
// View Students by Grade Scene - Shows available classes from uploads with Telegram info
const viewStudentsByGradeScene = new Scenes.BaseScene('view_students_by_grade_scene');
viewStudentsByGradeScene.enter(async (ctx) => {
    try {
        // Get all available classes from uploaded files
        const availableClasses = await getUniqueClasses();
        
        if (availableClasses.length === 0) {
            ctx.reply('❌ No classes found from uploaded lists. Please upload a student list first.');
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each class
        const classButtons = availableClasses.map(className => 
            [Markup.button.callback(
                className, 
                `view_class_${className.replace(/\s+/g, '_')}`
            )]
        );
        
        // Add cancel button
        classButtons.push([Markup.button.callback('❌ Cancel', 'cancel_view_students')]);
        
        ctx.reply('🎓 Select a class to view students:', Markup.inlineKeyboard(classButtons));
    } catch (error) {
        console.error('Error retrieving classes:', error);
        ctx.reply('❌ An error occurred while retrieving classes.');
        ctx.scene.leave();
    }
});

// Handle class selection - generate detailed list with Telegram info
viewStudentsByGradeScene.action(/^view_class_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const students = await Student.find({ class: new RegExp(className, 'i') }).sort({ name: 1 });
        if (students.length === 0) {
            ctx.reply(`❌ No students found in ${className}.`);
            return ctx.scene.leave();
        }
        
        // Get parent information for all students
        const studentPromises = students.map(async (student) => {
            let parentInfo = {
                telegramId: 'Not linked',
                username: 'N/A',
                name: 'N/A'
            };
            
            if (student.parentId) {
                const parentUser = await getUserById(student.parentId);
                if (parentUser) {
                    parentInfo = {
                        telegramId: parentUser.telegramId,
                        username: parentUser.username || 'N/A',
                        name: parentUser.name || 'N/A'
                    };
                } else {
                    parentInfo = {
                        telegramId: student.parentId,
                        username: 'Not found',
                        name: 'Not found'
                    };
                }
            }
            
            return { 
                ...student.toObject(), 
                parentInfo 
            };
        });
        
        const studentsWithParentInfo = await Promise.all(studentPromises);
        
        // Calculate column widths for proper formatting
        const maxNameLength = Math.max(...studentsWithParentInfo.map(s => s.name.length), 10);
        const maxParentNameLength = Math.max(...studentsWithParentInfo.map(s => s.parentInfo.name.length), 8);
        
        // Generate detailed list with Telegram information
        let fileContent = `DETAILED STUDENT LIST - ${className.toUpperCase()}\n`;
        fileContent += '='.repeat(120) + '\n';
        fileContent += `${'STUDENT NAME'.padEnd(maxNameLength)} - STUDENT ID - ${'PARENT NAME'.padEnd(maxParentNameLength)} - TELEGRAM ID - TELEGRAM USERNAME\n`;
        fileContent += '-'.repeat(maxNameLength) + ' - ' + '-'.repeat(10) + ' - ' + 
                      '-'.repeat(maxParentNameLength) + ' - ' + '-'.repeat(10) + ' - ' + '-'.repeat(15) + '\n';
        
        studentsWithParentInfo.forEach(student => {
            const paddedStudentName = student.name.padEnd(maxNameLength);
            const paddedParentName = student.parentInfo.name.padEnd(maxParentNameLength);
            
            fileContent += `${paddedStudentName} - ${student.studentId} - ${paddedParentName} - ${student.parentInfo.telegramId} - ${student.parentInfo.username}\n`;
        });
        
        fileContent += `\nTotal: ${studentsWithParentInfo.length} students\n`;
        fileContent += `Generated on: ${new Date().toLocaleString()}\n`;
        fileContent += 'Generated by School System Bot';
        
        const tempDir = './temp_exports';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        const filename = `students_detailed_${className.replace(/\s+/g, '_')}.txt`;
        const tempPath = path.join(tempDir, filename);
        fs.writeFileSync(tempPath, fileContent);
        
        await ctx.replyWithDocument({
            source: tempPath,
            filename: filename,
            caption: `📋 Detailed student list for ${className} (${studentsWithParentInfo.length} students)`
        });
        
        // Clean up
        if (fs.existsSync(tempPath)) {
            fs.unlinkSync(tempPath);
        }
        
    } catch (error) {
        console.error('Error viewing students:', error);
        ctx.reply('❌ An error occurred while retrieving students.');
    }
    ctx.scene.leave();
});

// Handle cancel action
viewStudentsByGradeScene.action('cancel_view_students', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ View students cancelled.', {
        reply_markup: { keyboard: studentManagementMenu.reply_markup.keyboard, resize_keyboard: true }
    });
    ctx.scene.leave();
});



stage.register(viewStudentsByGradeScene);
// Export IDs Scene
const exportIdsScene = new Scenes.BaseScene('export_ids_scene');

exportIdsScene.enter(async (ctx) => {
    try {
        // Get all processed uploads with class assignments
        const uploadedFiles = await UploadedFile.find({ 
            processed: true, 
            classAssigned: { $exists: true, $ne: null } 
        }).sort({ uploadDate: -1 });
        
        if (uploadedFiles.length === 0) {
            ctx.reply('❌ No processed class lists found. Please upload student lists first.');
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each class
        const classButtons = uploadedFiles.map(file => 
            [Markup.button.callback(
                `${file.classAssigned} (${new Date(file.uploadDate).toLocaleDateString()})`, 
                `export_ids_${file.id}`
            )]
        );
        
        // Add cancel button
        classButtons.push([Markup.button.callback('❌ Cancel', 'cancel_export')]);
        
        ctx.reply('📊 Select a class to export student IDs:', Markup.inlineKeyboard(classButtons));
    } catch (error) {
        console.error('Error retrieving uploaded files:', error);
        ctx.reply('❌ An error occurred while retrieving class lists.');
        ctx.scene.leave();
    }
});

// Handle class selection
exportIdsScene.action(/^export_ids_(.+)$/, async (ctx) => {
    const fileId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        // Get the uploaded file record
        const uploadedFile = await UploadedFile.findOne({ id: fileId });
        if (!uploadedFile) {
            ctx.reply('❌ Class list not found.');
            return ctx.scene.leave();
        }
        
        // Get all students from this class
        const students = await Student.find({ 
            class: uploadedFile.classAssigned 
        }).sort({ name: 1 });
        
        if (students.length === 0) {
            ctx.reply(`❌ No students found in class "${uploadedFile.classAssigned}".`);
            return ctx.scene.leave();
        }
        
        // Create a text file with only ID numbers
        const idList = students.map(student => student.studentId).join('\n');
        const fileName = `student_ids_${uploadedFile.classAssigned.replace(/\s+/g, '_')}.txt`;
        
        // Create temporary file
        const tempDir = './temp_exports';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        const tempPath = path.join(tempDir, fileName);
        fs.writeFileSync(tempPath, idList);
        
        // Send the file
        await ctx.replyWithDocument({
            source: tempPath,
            filename: fileName,
            caption: `📋 Student IDs for ${uploadedFile.classAssigned} (${students.length} students)`
        });
        
        // Clean up
        if (fs.existsSync(tempPath)) {
            fs.unlinkSync(tempPath);
        }
        
    } catch (error) {
        console.error('Error exporting IDs:', error);
        ctx.reply('❌ An error occurred while exporting student IDs.');
    }
    
    ctx.scene.leave();
});


stage.register(exportIdsScene);

// Edit Student Class Scene 



// ... (previous code from demo.js remains unchanged)

// --- Edit Student Scene ---
const editStudentScene = new Scenes.BaseScene('edit_student_scene');

editStudentScene.enter(async (ctx) => {
    try {
        // Track admin activity
        await trackAdminActivity(ctx, 'edit_student_initiated');
        
        // Notify master admin
        await notifyMasterAdmin(ctx, 'edit_student_initiated', {
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id
        });
        
        // Replace admin menu with cancel button in keyboard
        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel']
        ]).oneTime().resize();
        
        await ctx.reply(
            '✏️ Enter the Student ID (format: STXXXX) to edit:',
            cancelKeyboard
        );
    } catch (error) {
        console.error('Error entering edit student scene:', error);
        await trackAdminActivity(ctx, 'edit_student_error', { error: error.message });
        await notifyMasterAdmin(ctx, 'edit_student_error', { 
            error: error.message,
            adminId: ctx.from.id
        });
        await ctx.reply('❌ An error occurred.', adminMenu);
        await ctx.scene.leave();
    }
});

// Handle student ID input, field selection, and updates
editStudentScene.on('text', async (ctx) => {
    const input = ctx.message.text.trim();
    
    // Handle cancel command at any step
    if (input === '❌ Cancel') {
        await trackAdminActivity(ctx, 'edit_student_cancelled');
        await notifyMasterAdmin(ctx, 'edit_student_cancelled', { 
            admin: ctx.from.first_name || 'Admin',
            adminId: ctx.from.id
        });
        await ctx.reply('❌ Student edit cancelled.', adminMenu);
        delete ctx.session.studentToEdit;
        return ctx.scene.leave();
    }
    
    // Check if we're in the initial ID input step
    if (!ctx.session.studentToEdit) {
        // Validate student ID
        if (!isValidStudentId(input)) {
            return ctx.reply('❌ Invalid Student ID format. Please enter a valid ID (e.g., ST1234) or select "❌ Cancel".');
        }
        
        try {
            const student = await getStudentById(input);
            if (!student) {
                await ctx.reply('❌ Student not found with this ID.', adminMenu);
                return ctx.scene.leave();
            }
            
            // Store student ID in session
            ctx.session.studentToEdit = {
                studentId: student.studentId,
                step: 'select_field'
            };
            
            // Display current student details
            const parent = student.parentId ? await getUserById(student.parentId) : null;
            let studentInfo = `✏️ *EDIT STUDENT*\n\n` +
                `👤 Name: ${student.name}\n` +
                `🆔 ID: ${student.studentId}\n` +
                `🏫 Class: ${student.class}\n` +
                `👪 Parent: ${parent ? parent.name : 'None'}\n\n` +
                `Please select a field to edit:`;
            
            // Provide options to edit fields
            const editKeyboard = Markup.keyboard([
                ['✏️ Edit Name', '🏫 Edit Class'],
                ['👪 Edit Parent', '❌ Cancel']
            ]).oneTime().resize();
            
            await ctx.replyWithHTML(studentInfo, editKeyboard);
        } catch (error) {
            console.error('Error preparing student edit:', error);
            await trackAdminActivity(ctx, 'edit_student_preparation_error', { 
                studentId: input,
                error: error.message 
            });
            await notifyMasterAdmin(ctx, 'edit_student_preparation_error', { 
                studentId: input,
                error: error.message,
                adminId: ctx.from.id
            });
            await ctx.reply('❌ An error occurred.', adminMenu);
            delete ctx.session.studentToEdit;
            await ctx.scene.leave();
        }
    } else {
        const { studentId, step } = ctx.session.studentToEdit;
        
        if (step === 'select_field') {
            // Handle field selection
            if (!['✏️ Edit Name', '🏫 Edit Class', '👪 Edit Parent'].includes(input)) {
                return ctx.reply('❌ Please select a valid option or "❌ Cancel".');
            }
            
            try {
                const cancelKeyboard = Markup.keyboard([
                    ['❌ Cancel']
                ]).oneTime().resize();
                
                if (input === '✏️ Edit Name') {
                    ctx.session.studentToEdit.step = 'edit_name';
                    await ctx.reply('Enter the new name for the student:', cancelKeyboard);
                } else if (input === '🏫 Edit Class') {
                    ctx.session.studentToEdit.step = 'edit_class';
                    await ctx.reply('Enter the new class for the student:', cancelKeyboard);
                } else if (input === '👪 Edit Parent') {
                    ctx.session.studentToEdit.step = 'edit_parent';
                    await ctx.reply('Enter the Telegram ID of the new parent (or "None" to unlink):', cancelKeyboard);
                }
            } catch (error) {
                console.error('Error selecting field to edit:', error);
                await trackAdminActivity(ctx, 'edit_student_field_selection_error', { 
                    studentId,
                    error: error.message 
                });
                await notifyMasterAdmin(ctx, 'edit_student_field_selection_error', { 
                    studentId,
                    error: error.message,
                    adminId: ctx.from.id
                });
                await ctx.reply('❌ An error occurred.', adminMenu);
                delete ctx.session.studentToEdit;
                await ctx.scene.leave();
            }
        } else if (step === 'edit_name') {
            // Handle name update
            if (!input || input.length < 2) {
                return ctx.reply('❌ Name must be at least 2 characters long. Please try again or select "❌ Cancel".');
            }
            
            try {
                const student = await getStudentById(studentId);
                if (!student) {
                    await ctx.reply('❌ Student not found.', adminMenu);
                    delete ctx.session.studentToEdit;
                    return ctx.scene.leave();
                }
                
                const oldName = student.name;
                student.name = input;
                await student.save();
                
                await trackAdminActivity(ctx, 'student_name_updated', {
                    studentId,
                    oldName,
                    newName: input
                });
                await notifyMasterAdmin(ctx, 'student_name_updated', {
                    studentId,
                    oldName,
                    newName: input,
                    admin: ctx.from.first_name || 'Admin',
                    adminId: ctx.from.id
                });
                
                await ctx.reply(`✅ Student name updated to "${input}".`, adminMenu);
                delete ctx.session.studentToEdit;
                await ctx.scene.leave();
            } catch (error) {
                console.error('Error updating student name:', error);
                await trackAdminActivity(ctx, 'edit_student_name_error', { 
                    studentId,
                    error: error.message 
                });
                await notifyMasterAdmin(ctx, 'edit_student_name_error', { 
                    studentId,
                    error: error.message,
                    adminId: ctx.from.id
                });
                await ctx.reply('❌ An error occurred.', adminMenu);
                delete ctx.session.studentToEdit;
                await ctx.scene.leave();
            }
        } else if (step === 'edit_class') {
            // Handle class update
            if (!input || input.length < 1) {
                return ctx.reply('❌ Class name cannot be empty. Please try again or select "❌ Cancel".');
            }
            
            try {
                const student = await getStudentById(studentId);
                if (!student) {
                    await ctx.reply('❌ Student not found.', adminMenu);
                    delete ctx.session.studentToEdit;
                    return ctx.scene.leave();
                }
                
                const oldClass = student.class;
                student.class = input;
                await student.save();
                
                await trackAdminActivity(ctx, 'student_class_updated', {
                    studentId,
                    oldClass,
                    newClass: input
                });
                await notifyMasterAdmin(ctx, 'student_class_updated', {
                    studentId,
                    oldClass,
                    newClass: input,
                    admin: ctx.from.first_name || 'Admin',
                    adminId: ctx.from.id
                });
                
                await ctx.reply(`✅ Student class updated to "${input}".`, adminMenu);
                delete ctx.session.studentToEdit;
                await ctx.scene.leave();
            } catch (error) {
                console.error('Error updating student class:', error);
                await trackAdminActivity(ctx, 'edit_student_class_error', { 
                    studentId,
                    error: error.message 
                });
                await notifyMasterAdmin(ctx, 'edit_student_class_error', { 
                    studentId,
                    error: error.message,
                    adminId: ctx.from.id
                });
                await ctx.reply('❌ An error occurred.', adminMenu);
                delete ctx.session.studentToEdit;
                await ctx.scene.leave();
            }
        } else if (step === 'edit_parent') {
            // Handle parent update
            try {
                const student = await getStudentById(studentId);
                if (!student) {
                    await ctx.reply('❌ Student not found.', adminMenu);
                    delete ctx.session.studentToEdit;
                    return ctx.scene.leave();
                }
                
                let parentUpdateMsg = '';
                let oldParentId = student.parentId;
                let oldParentName = null;
                
                if (oldParentId) {
                    const oldParent = await getUserById(oldParentId);
                    oldParentName = oldParent ? oldParent.name : 'Unknown';
                }
                
                if (input.toLowerCase() === 'none') {
                    // Unlink parent
                    if (student.parentId) {
                        const parent = await getUserById(student.parentId);
                        if (parent) {
                            parent.studentIds = parent.studentIds.filter(id => id !== studentId);
                            if (parent.studentIds.length === 0) {
                                parent.role = 'user';
                                await trackAdminActivity(ctx, 'parent_demoted_to_user', {
                                    parentId: parent.telegramId,
                                    parentName: parent.name
                                });
                            }
                            await parent.save();
                            await trackAdminActivity(ctx, 'parent_unlinked', {
                                studentId: student.studentId,
                                studentName: student.name,
                                parentId: parent.telegramId,
                                parentName: parent.name
                            });
                        }
                        student.parentId = null;
                        await student.save();
                        parentUpdateMsg = 'Parent unlinked successfully.';
                    } else {
                        parentUpdateMsg = 'No parent was linked to this student.';
                    }
                } else {
                    // Link new parent
                    const newParent = await getUserById(input);
                    if (!newParent) {
                        return ctx.reply('❌ Parent with this Telegram ID not found. Please try again or select "❌ Cancel".');
                    }
                    
                    // Unlink old parent if exists
                    if (student.parentId && student.parentId !== input) {
                        const oldParent = await getUserById(student.parentId);
                        if (oldParent) {
                            oldParent.studentIds = oldParent.studentIds.filter(id => id !== studentId);
                            if (oldParent.studentIds.length === 0) {
                                oldParent.role = 'user';
                                await trackAdminActivity(ctx, 'parent_demoted_to_user', {
                                    parentId: oldParent.telegramId,
                                    parentName: oldParent.name
                                });
                            }
                            await oldParent.save();
                            await trackAdminActivity(ctx, 'parent_unlinked', {
                                studentId: student.studentId,
                                studentName: student.name,
                                parentId: oldParent.telegramId,
                                parentName: oldParent.name
                            });
                        }
                    }
                    
                    // Link new parent
                    newParent.studentIds = newParent.studentIds || [];
                    if (!newParent.studentIds.includes(studentId)) {
                        newParent.studentIds.push(studentId);
                    }
                    newParent.role = 'parent';
                    await newParent.save();
                    student.parentId = input;
                    await student.save();
                    parentUpdateMsg = `Parent updated to ${newParent.name}.`;
                }
                
                await trackAdminActivity(ctx, 'student_parent_updated', {
                    studentId,
                    oldParentId,
                    oldParentName,
                    newParentId: input.toLowerCase() === 'none' ? null : input,
                    newParentName: input.toLowerCase() === 'none' ? null : (await getUserById(input))?.name
                });
                await notifyMasterAdmin(ctx, 'student_parent_updated', {
                    studentId,
                    studentName: student.name,
                    oldParentId,
                    oldParentName,
                    newParentId: input.toLowerCase() === 'none' ? null : input,
                    newParentName: input.toLowerCase() === 'none' ? null : (await getUserById(input))?.name,
                    admin: ctx.from.first_name || 'Admin',
                    adminId: ctx.from.id
                });
                
                await ctx.reply(`✅ ${parentUpdateMsg}`, adminMenu);
                delete ctx.session.studentToEdit;
                await ctx.scene.leave();
            } catch (error) {
                console.error('Error updating student parent:', error);
                await trackAdminActivity(ctx, 'edit_student_parent_error', { 
                    studentId,
                    error: error.message 
                });
                await notifyMasterAdmin(ctx, 'edit_student_parent_error', { 
                    studentId,
                    error: error.message,
                    adminId: ctx.from.id
                });
                await ctx.reply('❌ An error occurred.', adminMenu);
                delete ctx.session.studentToEdit;
                await ctx.scene.leave();
            }
        }
    }
});

// Register the scene
stage.register(editStudentScene);

// ... (rest of the code from demo.js remains unchanged)



// Add Student Scene
const addStudentScene = new Scenes.BaseScene('add_student_scene');
addStudentScene.enter(async (ctx) => {
    ctx.reply('📝 Please provide the student\'s full name.');
});

addStudentScene.on('text', async (ctx) => {
    const studentName = ctx.message.text.trim();
    if (!isValidName(studentName)) {
        ctx.reply('❌ Invalid name. Please provide a non-empty name (max 100 characters).');
        return;
    }
    
    ctx.session.newStudentName = studentName;
    
    // Get all available classes from uploaded files
    const availableClasses = await getUniqueClasses();
    
    if (availableClasses.length === 0) {
        ctx.reply('No classes found. Please upload a student list first or enter the class name manually.');
        ctx.scene.enter('add_student_class_scene');
        return;
    }
    
    // Create inline keyboard with available classes
    const classButtons = availableClasses.map(className => 
        [Markup.button.callback(className, `select_class_${className}`)]
    );
    
    ctx.reply('Please select the class for this student:', Markup.inlineKeyboard(classButtons));
});

// Handle class selection
addStudentScene.action(/^select_class_(.+)$/, async (ctx) => {
    const className = ctx.match[1];
    await ctx.answerCbQuery();
    
    const studentName = ctx.session.newStudentName;
    if (!isValidClassName(className) || !isValidName(studentName)) {
        ctx.reply('❌ Invalid input. Please ensure name and class are valid.');
        ctx.session.newStudentName = null;
        return ctx.scene.leave();
    }
    
    const studentId = await generateUniqueStudentId();
    const newStudent = new Student({
        studentId,
        name: studentName,
        class: className,
        parentId: null,
        grades: {},
        schedule: { monday: 'N/A', tuesday: 'N/A' }
    });
    
    try {
        await newStudent.save();
        ctx.replyWithHTML(`✅ Student "${studentName}" added to class "${className}" with unique ID: **${studentId}**
_Share this ID with the parent for registration._`);
    } catch (error) {
        console.error('Error saving student:', error);
        ctx.reply('❌ Failed to add student. Please try again.');
    }
    
    ctx.session.newStudentName = null;
    ctx.scene.leave();
});


stage.register(addStudentScene);

const addStudentClassScene = new Scenes.BaseScene('add_student_class_scene');
addStudentClassScene.enter((ctx) => {
    ctx.reply('Please enter the student\'s class (e.g., Grade 5, Grade 8, Grade 10).');
});

addStudentClassScene.on('text', async (ctx) => {
    const studentClass = ctx.message.text.trim();
    const studentName = ctx.session.newStudentName;
    
    if (!isValidClassName(studentClass) || !isValidName(studentName)) {
        ctx.reply('❌ Invalid input. Please ensure name and class are valid.');
        ctx.session.newStudentName = null;
        return ctx.scene.leave();
    }
    
    const studentId = await generateUniqueStudentId();
    const newStudent = new Student({
        studentId,
        name: studentName,
        class: studentClass,
        parentId: null,
        grades: {},
        schedule: { monday: 'N/A', tuesday: 'N/A' }
    });
    
    try {
        await newStudent.save();
        ctx.replyWithHTML(`✅ Student "${studentName}" added to class "${studentClass}" with unique ID: **${studentId}**
_Share this ID with the parent for registration._`);
    } catch (error) {
        console.error('Error saving student:', error);
        ctx.reply('❌ Failed to add student. Please try again.');
    }
    
    ctx.session.newStudentName = null;
    ctx.scene.leave();
});

stage.register(addStudentClassScene);

//
//
//
//uploadStudentListScene
//
//


const uploadStudentListScene = new Scenes.BaseScene('upload_student_list_scene');

uploadStudentListScene.enter((ctx) => {
  ctx.reply('📂 Please upload a text file with student names (one per line).');
});

uploadStudentListScene.on('document', async (ctx) => {
  try {
    const file = ctx.message.document;
    if (!file) {
      return ctx.reply('❌ No file detected. Please upload again.');
    }

    // Download file to temp folder
    const fileLink = await ctx.telegram.getFileLink(file.file_id);
    const tempDir = './temp_uploads';
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    const storedName = `${Date.now()}_${file.file_name}`;
    const tempUploadPath = path.join(tempDir, storedName);

    const response = await fetch(fileLink.href);
    const buffer = await response.buffer();
    fs.writeFileSync(tempUploadPath, buffer);

    ctx.session.tempUploadPath = tempUploadPath;
    ctx.session.uploadedFileMeta = {
      id: crypto.randomBytes(8).toString('hex'),
      originalName: file.file_name,
      storedName
    };

    ctx.reply('✅ File uploaded. Now enter the class name this list belongs to:');
  } catch (err) {
    console.error('File upload error:', err);
    ctx.reply('❌ Failed to upload file. Try again.');
    ctx.scene.leave();
  }
});

uploadStudentListScene.on('text', async (ctx) => {
  const className = ctx.message.text.trim();
  if (!isValidClassName(className)) {
    return ctx.reply('❌ Invalid class name. Max 50 characters.');
  }

  const { tempUploadPath, uploadedFileMeta } = ctx.session;
  if (!tempUploadPath || !uploadedFileMeta) {
    ctx.reply('❌ Session error. Please upload again.');
    return ctx.scene.leave();
  }

  try {
    if (!fs.existsSync(tempUploadPath)) {
      ctx.reply('❌ Temporary file not found. Please upload again.');
      return ctx.scene.leave();
    }

    const fileContent = fs.readFileSync(tempUploadPath, 'utf8');
    const studentNames = fileContent.split(/\r?\n/)
      .map(name => name.trim())
      .filter(name => name && isValidName(name));

    if (studentNames.length === 0) {
      ctx.reply('❌ No valid names found in the file.');
      fs.unlinkSync(tempUploadPath);
      delete ctx.session.tempUploadPath;
      return ctx.scene.leave();
    }

    // Initial progress message
    const total = studentNames.length;
    const etaSeconds = Math.ceil(total * 0.1); // ~100ms per student
    const progressMsg = await ctx.reply(
      `⏳ Processing ${total} students...\nEstimated time: ~${etaSeconds}s`,
      Markup.inlineKeyboard([[Markup.button.callback('⏳ Please wait...', 'processing_disabled')]])
    );

    let addedCount = 0;
    let errorCount = 0;
    const startTime = Date.now();

    for (let i = 0; i < total; i++) {
      const name = studentNames[i];
      try {
        const studentId = await generateUniqueStudentId();
        const newStudent = new Student({
          studentId,
          name,
          class: className,
          parentId: null
        });
        await newStudent.save();
        addedCount++;
      } catch {
        errorCount++;
      }

      // Update progress every 10 students or at the end
      if ((i + 1) % 10 === 0 || i + 1 === total) {
        const elapsed = (Date.now() - startTime) / 1000;
        const rate = elapsed / (i + 1);
        const remaining = Math.ceil(rate * (total - (i + 1)));

        await ctx.telegram.editMessageText(
          progressMsg.chat.id,
          progressMsg.message_id,
          null,
          `⏳ Processing students...\n` +
          `Progress: ${i + 1}/${total}\n` +
          `ETA: ~${remaining}s`
        );
      }
    }

    // Save upload metadata
    const savedUpload = await new UploadedFile({
      ...uploadedFileMeta,
      uploadDate: new Date(),
      processed: true,
      classAssigned: className
    }).save();

    // Log admin activity
    await trackAdminActivity(ctx, 'upload_document', {
      uploadedFile: {
        id: savedUpload.id,
        originalName: savedUpload.originalName,
        storedName: savedUpload.storedName,
        classAssigned: savedUpload.classAssigned
      },
      totals: { added: addedCount, errors: errorCount }
    });

    // Final result
    await ctx.telegram.editMessageText(
      progressMsg.chat.id,
      progressMsg.message_id,
      null,
      `✅ Finished processing ${total} students!\n` +
      `➕ Added: ${addedCount}, ❌ Errors: ${errorCount}`
    );

  } catch (error) {
    console.error('File processing error:', error);
    ctx.reply('❌ An error occurred while processing the file.');
  } finally {
    if (tempUploadPath && fs.existsSync(tempUploadPath)) fs.unlinkSync(tempUploadPath);
    delete ctx.session.tempUploadPath;
    delete ctx.session.uploadedFileMeta;
    ctx.scene.leave();
  }
});

stage.register(uploadStudentListScene);


//registerParentScene
const registerParentScene = new Scenes.BaseScene('register_parent_scene');

// Step 1: Enter scene
registerParentScene.enter((ctx) => {
    ctx.reply('🔗 Please enter your Student ID:');
});

// Step 2: Parent enters Student ID
registerParentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    const student = await Student.findOne({ studentId });

    if (!student) {
        return ctx.reply('❌ Student not found. Please enter a valid Student ID.');
    }

    // Save to session for confirmation
    ctx.session.pendingRegisterStudentId = studentId;

    ctx.reply(
        `📌 *Student Profile Found*\n\n` +
        `👤 Name: *${student.name}*\n` +
        `🆔 ID: *${student.studentId}*\n` +
        `🏫 Class: *${student.class}*\n\n` +
        `Do you want to register as parent of this student?`,
        {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: [
                    [
                        { text: '✅ Confirm', callback_data: 'register_parent_confirm' },
                        { text: '❌ Cancel', callback_data: 'register_parent_cancel' }
                    ]
                ]
            }
        }
    );
});

// Step 3: Cancel
registerParentScene.action('register_parent_cancel', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Registration cancelled.', loginMenu);
    ctx.scene.leave();
});

// Step 4: Confirm → create pending link request
registerParentScene.action('register_parent_confirm', async (ctx) => {
    await ctx.answerCbQuery();

    const studentId = ctx.session.pendingRegisterStudentId;
    if (!studentId) {
        ctx.reply('❌ No student selected.');
        return ctx.scene.leave();
    }

    const student = await Student.findOne({ studentId });
    if (!student) {
        ctx.reply('❌ Student not found.');
        return ctx.scene.leave();
    }

    // Check if already linked
    if (student.parentId || student.pendingParentId) {
        ctx.reply('❌ This student is already linked or pending approval.');
        return ctx.scene.leave();
    }

    // Save pending link
    student.pendingParentId = ctx.from.id;
    await student.save();

    // Create parent user if not exists
    let parent = await User.findOne({ telegramId: ctx.from.id });
    if (!parent) {
        parent = new User({
            telegramId: ctx.from.id,
            name: ctx.from.first_name || 'Parent',
            role: 'parent',
            pendingStudentIds: [studentId]
        });
    } else {
        parent.role = 'parent';
        parent.pendingStudentIds.push(studentId);
    }
    await parent.save();

    // Notify admins
    const admins = await User.find({ role: 'admin' });
    for (const admin of admins) {
        await ctx.telegram.sendMessage(
            admin.telegramId,
            `📝 *New Parent Registration Request*\n\n` +
            `👤 Parent: ${parent.name}\n` +
            `🆔 Parent ID: ${parent.telegramId}\n\n` +
            `👨‍🎓 Student: *${student.name}* (${student.studentId})\n` +
            `🏫 Class: ${student.class}\n\n` +
            `Do you approve this registration?`,
            {
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [
                            { text: '✅ Approve', callback_data: `link_yes_${parent.telegramId}_${student.studentId}` },
                            { text: '❌ Deny', callback_data: `link_no_${parent.telegramId}_${student.studentId}` }
                        ]
                    ]
                }
            }
        );
    }

    ctx.reply('📨 Registration request sent to administrators for approval.', loginMenu);
    ctx.scene.leave();
});

// ✅ Register scene
stage.register(registerParentScene);
//linkanother student
const linkAnotherStudentScene = new Scenes.BaseScene('link_another_student_scene');

// Step 1: Enter scene
linkAnotherStudentScene.enter((ctx) => {
    ctx.reply('🔗 Please enter the Student ID to link:');
});

// Step 2: Parent enters student ID
linkAnotherStudentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    const student = await Student.findOne({ studentId });

    if (!student) {
        return ctx.reply('❌ Student not found. Please enter a valid student ID.');
    }

    // Save for confirmation
    ctx.session.pendingLinkStudentId = studentId;

    ctx.reply(
        `👨‍🎓 *Student Found*\n\n` +
        `👤 Name: ${student.name}\n` +
        `🏫 Class: ${student.class}\n\n` +
        `Do you want to send a link request for this student?`,
        {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: [
                    [
                        { text: '✅ Confirm', callback_data: 'link_confirm' },
                        { text: '❌ Cancel', callback_data: 'link_cancel' }
                    ]
                ]
            }
        }
    );
});

// Step 3: Cancel
linkAnotherStudentScene.action('link_cancel', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Link request cancelled.', parentMenu);
    ctx.scene.leave();
});

// Step 4: Confirm
linkAnotherStudentScene.action('link_confirm', async (ctx) => {
    await ctx.answerCbQuery();

    const studentId = ctx.session.pendingLinkStudentId;
    if (!studentId) {
        ctx.reply('❌ No student selected.');
        return ctx.scene.leave();
    }

    const student = await Student.findOne({ studentId });
    if (!student) {
        ctx.reply('❌ Student not found.');
        return ctx.scene.leave();
    }

    const parent = await User.findOne({ telegramId: ctx.from.id, role: 'parent' });
    if (!parent) {
        ctx.reply('❌ You are not registered as a parent.');
        return ctx.scene.leave();
    }

    // ✅ Limit check
    if (parent.studentIds.length >= 3) {
        ctx.reply('❌ You cannot link more than 3 students to your account.');
        return ctx.scene.leave();
    }

    // Already linked/pending check
    if (student.parentId || student.pendingParentId ||
        parent.studentIds.includes(studentId) || parent.pendingStudentIds.includes(studentId)) {
        ctx.reply('❌ This student is already linked or pending approval.');
        return ctx.scene.leave();
    }

    // Save pending link
    student.pendingParentId = ctx.from.id;
    await student.save();

    parent.pendingStudentIds.push(studentId);
    await parent.save();

    // Notify admins with approve/deny buttons
    const admins = await User.find({ role: 'admin' });
    for (const admin of admins) {
        await ctx.telegram.sendMessage(
            admin.telegramId,
            `🔗 *New Link Request*\n\n` +
            `👤 Parent: ${parent.name}\n` +
            `🆔 Parent ID: ${parent.telegramId}\n` +
            `👨‍🎓 Student: ${student.name} (${student.studentId})\n` +
            `🏫 Class: ${student.class}\n\n` +
            `Do you approve this link request?`,
            {
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [
                            { text: '✅ Approve', callback_data: `link_yes_${parent.telegramId}_${student.studentId}` },
                            { text: '❌ Deny', callback_data: `link_no_${parent.telegramId}_${student.studentId}` }
                        ]
                    ]
                }
            }
        );
    }

    ctx.reply('📨 Link request sent to administrators for approval.', parentMenu);
    ctx.scene.leave();
});

// ✅ Register scene
stage.register(linkAnotherStudentScene);
//Admin Login Scene - Updated to handle new admin ID format if needed
const adminLoginScene = new Scenes.BaseScene('admin_login_scene');
adminLoginScene.enter(async (ctx) => {
    try {
        // Check if already registered
        const existingUser = await User.findOne({ adminId: ctx.from.id });

        if (existingUser) {
            ctx.reply(
                `❌ You are already registered.\n\n` +
                `👤 Name: ${existingUser.name}\n` +
                `🎭 Role: ${existingUser.role}\n\n` +
                `⚠️ You cannot have multiple roles on the same account.`
            );
            return ctx.scene.leave(); // exit scene
        }

        // If not registered, ask for admin key
        ctx.reply('🔑 Please enter the admin key to register as administrator:');
        ctx.session.awaitingAdminKey = true;

    } catch (err) {
        console.error('Error entering admin registration scene:', err);
        ctx.reply('❌ Failed to start admin registration. Please try again later.');
        ctx.scene.leave();
    }
});
adminLoginScene.on('text', async (ctx) => {
    const code = ctx.message.text.trim();
    if (code === process.env.ADMIN_SECRET_CODE) {
        let admin = await getUserById(ctx.from.id);
        if (!admin) {
            admin = new User({
                telegramId: ctx.from.id,
                role: 'admin',
                name: ctx.from.first_name || 'Admin',
                adminId: await generateUniqueAdminId() // Add admin ID if you want to store it
            });
            await admin.save();
        } else {
            admin.role = 'admin';
            // Add admin ID if not already set
            if (!admin.adminId) {
                admin.adminId = await generateUniqueAdminId();
            }
            await admin.save();
        }
        ctx.reply('✅ Admin login successful!', adminMenu);
    } else {
        ctx.reply('❌ Invalid code. Access denied.');
    }
    ctx.scene.leave();
});
stage.register(adminLoginScene);


// Unbind Parent Scene
// Unbind Parent Scene
const unbindParentScene = new Scenes.BaseScene('unbind_parent_scene');

unbindParentScene.enter((ctx) => {
    ctx.reply(
        '🆔 Please provide the student ID to unbind the parent from, or press ❌ Cancel.',
        Markup.keyboard([['❌ Cancel']]).oneTime().resize()
    );
});

unbindParentScene.on('text', async (ctx) => {
    const input = ctx.message.text.trim();

    // Handle cancel option
    if (input === '❌ Cancel') {
        await ctx.reply('❌ Unbind operation cancelled.', adminMenu);
        return ctx.scene.leave();
    }

    // Handle normal student ID flow
    if (!isValidStudentId(input)) {
        return ctx.reply('❌ Invalid Student ID. Please provide a 10-digit ID or press ❌ Cancel.');
    }

    try {
        const student = await getStudentById(input);
        if (student && student.parentId) {
            const parent = await getUserById(student.parentId);
            if (parent) {
                parent.studentIds = parent.studentIds.filter(id => id !== input);
                if (parent.studentIds.length === 0) {
                    parent.role = 'user';
                }
                await parent.save();
            }
            student.parentId = null;
            await student.save();
            ctx.reply(`✅ Parent unbound from student ${student.name} (ID: ${input}).`, adminMenu);
        } else {
            ctx.reply('❌ Student ID not found or no parent linked.', adminMenu);
        }
    } catch (error) {
        console.error('Error in unbind parent scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', adminMenu);
    }

    ctx.scene.leave();
});

stage.register(unbindParentScene);

const editStudentNameScene = new Scenes.BaseScene('edit_student_name_scene');
editStudentNameScene.enter((ctx) => ctx.reply('Please enter the new name for the student.'));
editStudentNameScene.on('text', async (ctx) => {
    const newName = ctx.message.text.trim();
    if (!isValidName(newName)) {
        ctx.reply('❌ Invalid name. Please provide a non-empty name (max 100 characters).');
        return;
    }
    try {
        const student = await getStudentById(ctx.session.editStudentId);
        if (student && newName) {
            // Clean up any invalid grade entries before saving
            if (student.grades && Array.isArray(student.grades)) {
                student.grades = student.grades.filter(grade => 
                    grade && 
                    grade.score && 
                    grade.purpose && 
                    grade.gradeId && 
                    grade.subject && 
                    grade.teacherId
                );
            }
            
            student.name = newName;
            await student.save();
            ctx.reply(`✅ Student name updated to "${newName}".`);
        } else {
            ctx.reply('❌ Invalid name or student ID.');
        }
    } catch (error) {
        console.error('Error in edit student name scene:', error);
        
        // More specific error handling
        if (error.name === 'ValidationError') {
            ctx.reply('❌ Validation error. The student data contains invalid information. Please contact an administrator.');
        } else {
            ctx.reply('❌ An error occurred. Please try again.');
        }
    }
    ctx.scene.leave();
});
stage.register(editStudentNameScene);


// ===== EDIT TEACHER FUNCTIONALITY =====

// Edit Teacher Scene - Shows list of registered teachers
const editTeacherScene = new Scenes.BaseScene('edit_teacher_scene');

editTeacherScene.enter(async (ctx) => {
    try {
        // Get all registered teachers
        const teachers = await Teacher.find().sort({ name: 1 });
        
        if (teachers.length === 0) {
            ctx.reply('❌ No teachers found. Please add teachers first.');
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each teacher
        const teacherButtons = teachers.map(teacher => 
            [Markup.button.callback(
                `${teacher.name} (ID: ${teacher.teacherId})`, 
                `select_teacher_${teacher.teacherId}`
            )]
        );
        
        // Add cancel button
        teacherButtons.push([Markup.button.callback('❌ Cancel', 'cancel_edit_teacher')]);
        
        ctx.reply('🧑🏫 Select a teacher to edit:', Markup.inlineKeyboard(teacherButtons));
    } catch (error) {
        console.error('Error retrieving teachers:', error);
        ctx.reply('❌ An error occurred while retrieving teachers.');
        ctx.scene.leave();
    }
});

// Handle teacher selection
editTeacherScene.action(/^select_teacher_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const teacher = await getTeacherById(teacherId);
        if (!teacher) {
            ctx.reply('❌ Teacher not found. Please try again.');
            return ctx.scene.leave();
        }
        
        // Store teacher info in session
        ctx.session.editTeacherId = teacherId;
        ctx.session.editTeacherName = teacher.name;
        
// In the editTeacherScene.action(/^select_teacher_(.+)$/ handler, update the message:
let subjectsInfo = teacher.subjects.length > 0 ? 
    teacher.subjects.join(', ') : 
    'No subjects assigned';

// Add telegramInfo definition
let telegramInfo = teacher.telegramId ? 
    `${teacher.telegramId}` : 
    'Not linked';

ctx.replyWithHTML(
    `📋 *Teacher Information:*\n` +
    `• Name: ${teacher.name}\n` +
    `• ID: ${teacher.teacherId}\n` +
    `• Telegram ID: ${telegramInfo}\n` +
    `• Subjects: ${subjectsInfo}\n\n` +
    `Which field do you want to edit?`,
    Markup.inlineKeyboard([
        [Markup.button.callback('✏️ Name', 'edit_teacher_name')],
        [Markup.button.callback('📚 Manage Subjects', 'edit_teacher_subjects')],
        [Markup.button.callback('🔗 Telegram ID', 'edit_teacher_telegram')],
        [Markup.button.callback('⬅️ Cancel', 'cancel_edit_teacher')]
    ])
);
    } catch (error) {
        console.error('Error in edit teacher scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
        ctx.scene.leave();
    }
});

// Handle cancel action
editTeacherScene.action('cancel_edit_teacher', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Edit cancelled.', {
        reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
    });
    ctx.scene.leave();
});


// Edit Teacher Name Scene
const editTeacherNameScene = new Scenes.BaseScene('edit_teacher_name_scene');
editTeacherNameScene.enter((ctx) => ctx.reply('Please enter the new name for the teacher.'));
editTeacherNameScene.on('text', async (ctx) => {
    const newName = ctx.message.text.trim();
    if (!isValidName(newName)) {
        ctx.reply('❌ Invalid name. Please provide a non-empty name (max 100 characters).');
        return;
    }
    try {
        const teacher = await getTeacherById(ctx.session.editTeacherId);
        if (teacher && newName) {
            teacher.name = newName;
            await teacher.save();
            const user = await getUserById(teacher.telegramId);
            if (user) {
                user.name = newName;
                await user.save();
            }
            ctx.reply(`✅ Teacher name updated to "${newName}".`);
        } else {
            ctx.reply('❌ Invalid name or teacher ID.');
        }
    } catch (error) {
        console.error('Error in edit teacher name scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});

// Enhanced Edit Teacher Subjects Scene with Remove: Subject format
const editTeacherSubjectsScene = new Scenes.BaseScene('edit_teacher_subjects_scene');

editTeacherSubjectsScene.enter(async (ctx) => {
    try {
        const teacherId = ctx.session.editTeacherId;
        const teacher = await getTeacherById(teacherId);
        
        if (!teacher) {
            ctx.reply('❌ Teacher not found.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        const subjects = teacher.subjects || [];
        
        if (subjects.length === 0) {
            ctx.reply('📚 This teacher has no subjects assigned yet.', Markup.inlineKeyboard([
                [Markup.button.callback('➕ Add Subject', 'add_new_subject_to_teacher')],
                [Markup.button.callback('⬅️ Back to Teacher Edit', 'back_to_teacher_edit')]
            ]));
            return;
        }
        
        let message = `📚 *Current Subjects for ${teacher.name}:*\n\n`;
        
        subjects.forEach((subject, index) => {
            message += `${index + 1}. ${subject}\n`;
        });
        
        // Create inline buttons with "Remove: Subject" format
        const subjectButtons = subjects.map(subject => 
            [Markup.button.callback(`🗑️ Remove: ${subject}`, `remove_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add add button and back button
        subjectButtons.push(
            [Markup.button.callback('➕ Add Subject', 'add_new_subject_to_teacher')],
            [Markup.button.callback('⬅️ Back to Teacher Edit', 'back_to_teacher_edit')]
        );
        
        ctx.replyWithHTML(message, Markup.inlineKeyboard(subjectButtons));
        
    } catch (error) {
        console.error('Error in edit teacher subjects scene:', error);
        ctx.reply('❌ An error occurred while retrieving subjects.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        ctx.scene.leave();
    }
});

// Handle subject removal
editTeacherSubjectsScene.action(/^remove_subject_(.+)$/, async (ctx) => {
    const subjectToRemove = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const teacherId = ctx.session.editTeacherId;
        const teacher = await getTeacherById(teacherId);
        
        if (!teacher) {
            ctx.reply('❌ Teacher not found.');
            return ctx.scene.leave();
        }
        
        // Remove the subject
        teacher.subjects = teacher.subjects.filter(s => s !== subjectToRemove);
        await teacher.save();
        
        // Update user record if it exists
        if (teacher.telegramId) {
            const user = await getUserById(teacher.telegramId);
            if (user) {
                user.subjects = user.subjects.filter(s => s !== subjectToRemove);
                await user.save();
            }
        }
        
        ctx.reply(`✅ Subject "${subjectToRemove}" has been removed from ${teacher.name}.`);
        
        // Refresh the subject list
        setTimeout(() => {
            ctx.scene.reenter();
        }, 1000);
        
    } catch (error) {
        console.error('Error removing subject:', error);
        ctx.reply('❌ An error occurred while removing the subject.');
        ctx.scene.leave();
    }
});

// Handle add new subject
editTeacherSubjectsScene.action('add_new_subject_to_teacher', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('📝 Please enter the new subject to add:');
    ctx.scene.enter('add_subject_to_teacher_scene');
});

// Handle back to teacher edit
editTeacherSubjectsScene.action('back_to_teacher_edit', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('edit_teacher_scene');
});

// Add menu return handler
editTeacherSubjectsScene.hears(['⬅️ Main Menu', '🏠 Main Menu', '↩️ Main Menu', '🔙 Main Menu'], async (ctx) => {
    await returnToM
});

// Add Subject to Teacher Scene
const addSubjectToTeacherScene = new Scenes.BaseScene('add_subject_to_teacher_scene');

addSubjectToTeacherScene.enter((ctx) => {
    ctx.reply('📝 Please enter the new subject to add to this teacher:');
});

addSubjectToTeacherScene.on('text', async (ctx) => {
    const newSubject = ctx.message.text.trim();
    
    if (!isValidSubject(newSubject)) {
        ctx.reply('❌ Invalid subject. Please enter a non-empty subject name (max 50 characters).');
        return;
    }
    
    try {
        const teacherId = ctx.session.editTeacherId;
        const teacher = await getTeacherById(teacherId);
        
        if (!teacher) {
            ctx.reply('❌ Teacher not found.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        // Check if subject already exists
        if (teacher.subjects.includes(newSubject)) {
            ctx.reply(`❌ Subject "${newSubject}" is already assigned to this teacher.`);
            return ctx.scene.leave();
        }
        
        // Add the subject
        teacher.subjects.push(newSubject);
        await teacher.save();
        
        // Update user record if it exists
        if (teacher.telegramId) {
            const user = await getUserById(teacher.telegramId);
            if (user) {
                if (!user.subjects.includes(newSubject)) {
                    user.subjects.push(newSubject);
                    await user.save();
                }
            }
        }
        
        ctx.reply(`✅ Subject "${newSubject}" has been added to ${teacher.name}.`);
        
        // Return to subjects management
        setTimeout(() => {
            ctx.scene.enter('edit_teacher_subjects_scene');
        }, 1000);
        
    } catch (error) {
        console.error('Error adding subject to teacher:', error);
        ctx.reply('❌ An error occurred while adding the subject.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        ctx.scene.leave();
    }
});

// Handle back to subjects
addSubjectToTeacherScene.action('back_to_subjects', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('edit_teacher_subjects_scene');
});

addSubjectToTeacherScene.hears(['⬅️ Back', '🔙 Back'], async (ctx) => {
    ctx.scene.enter('edit_teacher_subjects_scene');
});

// Add menu return handler
addSubjectToTeacherScene.hears(['⬅️ Main Menu', '🏠 Main Menu', '↩️ Main Menu', '🔙 Main Menu'], async (ctx) => {
    await returnToMenu(ctx, '❌ Subject addition cancelled.');
});
stage.register(addSubjectToTeacherScene);

// Edit Teacher Telegram ID Scene
const editTeacherTelegramScene = new Scenes.BaseScene('edit_teacher_telegram_scene');
editTeacherTelegramScene.enter((ctx) => {
    ctx.reply('📱 Please enter the new Telegram ID for the teacher.');
});
editTeacherTelegramScene.on('text', async (ctx) => {
    const newTelegramId = ctx.message.text.trim();
    
    if (!isValidTelegramId(newTelegramId)) {
        ctx.reply('❌ Invalid Telegram ID. Please provide a valid numeric Telegram ID.');
        return;
    }
    
    try {
        const teacherId = ctx.session.editTeacherId;
        const teacher = await getTeacherById(teacherId);
        
        if (!teacher) {
            ctx.reply('❌ Teacher not found.');
            return ctx.scene.leave();
        }
        
        // Check if Telegram ID is already linked to another teacher
        const existingTeacher = await Teacher.findOne({ telegramId: newTelegramId });
        if (existingTeacher && existingTeacher.teacherId !== teacherId) {
            ctx.reply(`❌ This Telegram ID is already linked to teacher ${existingTeacher.name}.`);
            return ctx.scene.leave();
        }
        
        // Update teacher record
        const oldTelegramId = teacher.telegramId;
        teacher.telegramId = newTelegramId;
        await teacher.save();
        
        // Update user record if it exists
        if (oldTelegramId) {
            const oldUser = await getUserById(oldTelegramId);
            if (oldUser) {
                oldUser.role = 'user'; // Demote to user role
                await oldUser.save();
            }
        }
        
        // Create or update user record for new Telegram ID
        let newUser = await getUserById(newTelegramId);
        if (!newUser) {
            newUser = new User({
                telegramId: newTelegramId,
                name: teacher.name,
                role: 'teacher',
                subjects: teacher.subjects
            });
        } else {
            newUser.role = 'teacher';
            newUser.name = teacher.name;
            newUser.subjects = teacher.subjects;
        }
        await newUser.save();
        
        ctx.reply(`✅ Teacher Telegram ID updated to ${newTelegramId}.`, {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        
    } catch (error) {
        console.error('Error updating teacher Telegram ID:', error);
        ctx.reply('❌ An error occurred while updating Telegram ID.');
    }
    
    ctx.scene.leave();
});


// ===== REGISTER ALL TEACHER SCENES =====
stage.register(editTeacherScene);
stage.register(editTeacherNameScene);
stage.register(editTeacherSubjectsScene);
stage.register(editTeacherTelegramScene);

// Announcement Recipient Scene - Updated with All Admins option
const announcementRecipientScene = new Scenes.BaseScene('announcement_recipient_scene');
announcementRecipientScene.enter((ctx) => {
    ctx.reply('📢 Who do you want to send the announcement to?', Markup.inlineKeyboard([
        [Markup.button.callback('👑 All Admins', 'announce_admins')],
        [Markup.button.callback('👨‍👩‍👧‍👦 All Parents', 'announce_parents')],
        [Markup.button.callback('🧑🏫 All Teachers', 'announce_teachers')],
        [Markup.button.callback('❌ Cancel', 'cancel_announcement')]
    ]));
});

announcementRecipientScene.action('announce_admins', async (ctx) => {
    ctx.session.announcementTarget = 'admins';
    await ctx.answerCbQuery();
    await ctx.reply('📝 Please send the announcement message or media to send to all admins.');
    ctx.scene.enter('send_announcement_scene');
});

announcementRecipientScene.action('announce_parents', async (ctx) => {
    ctx.session.announcementTarget = 'parents';
    await ctx.answerCbQuery();
    await ctx.reply('📝 Please send the announcement message to send to all parents.');
    ctx.scene.enter('send_announcement_scene');
});

announcementRecipientScene.action('announce_teachers', async (ctx) => {
    ctx.session.announcementTarget = 'teachers';
    await ctx.answerCbQuery();
    await ctx.reply('📝 Please send the announcement message to send to all teachers.');
    ctx.scene.enter('send_announcement_scene');
});

announcementRecipientScene.action('cancel_announcement', async (ctx) => {
    await ctx.answerCbQuery();
    await ctx.reply('❌ Announcement cancelled.', adminMenu);
    ctx.scene.leave();
});
stage.register(announcementRecipientScene);
//sendAnnouncementScene
const sendAnnouncementScene = new Scenes.BaseScene('send_announcement_scene');

sendAnnouncementScene.enter(async (ctx) => {
  ctx.reply('📝 Please send the announcement message or media you want to send.');
});

sendAnnouncementScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
  // Extract announcement text or caption
  const isText = ctx.message.text || false;
  const isMedia =
    ctx.message.photo || ctx.message.video || ctx.message.document || ctx.message.audio || ctx.message.voice;

  let announcementText = '';
  if (isText) {
    announcementText = ctx.message.text.trim();
    if (!announcementText) {
      ctx.reply('❌ Announcement cannot be empty. Please send the announcement message or media again.');
      return;
    }
  } else if (isMedia) {
    // Use caption if available or empty string
    announcementText = ctx.message.caption ? ctx.message.caption.trim() : '';
  }

  const target = ctx.session.announcementTarget;
  if (!target) {
    ctx.reply('❌ Target audience not set. Please start again.');
    return ctx.scene.leave();
  }

  // Get sender's Telegram name for display
  const senderName = ctx.from.first_name || ctx.from.username || 'Admin';

  try {
    // Determine recipients by role
    let recipients;
    if (target === 'admins') {
      recipients = await User.find({ role: 'admin' });
    } else if (target === 'parents') {
      recipients = await User.find({ role: 'parent' });
    } else if (target === 'teachers') {
      recipients = await User.find({ role: 'teacher' });
    } else {
      ctx.reply('❌ Invalid target audience.');
      return ctx.scene.leave();
    }

    // Filter out the sender from recipients to avoid sending to themselves
    const filteredRecipients = recipients.filter(recipient => recipient.telegramId !== ctx.from.id.toString());

    let successCount = 0;
    let failedCount = 0;

    for (const user of filteredRecipients) {
      try {
        // Send appropriate message based on content type
        if (isText) {
          // Send text announcement
          await ctx.telegram.sendMessage(
            user.telegramId,
            `📢 *Announcement from ${senderName}:*\n${announcementText}`,
            { parse_mode: "HTML" }
          );
          successCount++;
        } else if (isMedia) {
          // Send media with optional caption prepended with announcement header
          const caption = announcementText
            ? `📢 *Announcement from ${senderName}:*\n${announcementText}`
            : `📢 Announcement from ${senderName}`;

          if (ctx.message.photo) {
            // Photo array, send highest resolution photo
            const photoArray = ctx.message.photo;
            const highestResPhoto = photoArray[photoArray.length - 1];
            await ctx.telegram.sendPhoto(user.telegramId, highestResPhoto.file_id, {
              caption,
              parse_mode: "HTML"
            });
            successCount++;
          } else if (ctx.message.video) {
            await ctx.telegram.sendVideo(user.telegramId, ctx.message.video.file_id, {
              caption,
              parse_mode: "HTML"
            });
            successCount++;
          } else if (ctx.message.document) {
            await ctx.telegram.sendDocument(user.telegramId, ctx.message.document.file_id, {
              caption,
              parse_mode: "HTML"
            });
            successCount++;
          } else if (ctx.message.audio) {
            await ctx.telegram.sendAudio(user.telegramId, ctx.message.audio.file_id, {
              caption,
              parse_mode: "HTML"
            });
            successCount++;
          } else if (ctx.message.voice) {
            await ctx.telegram.sendVoice(user.telegramId, ctx.message.voice.file_id, {
              caption,
              parse_mode: "HTML"
            });
            successCount++;
          }
        }
      } catch (error) {
        if (error.response && error.response.error_code === 403) {
          console.log(`User ${user.telegramId} has blocked the bot.`);
          failedCount++;
        } else {
          console.error(`Failed to send announcement to ${user.telegramId}:`, error);
          failedCount++;
        }
      }
    }

    // Send summary to the sender
    let summaryMessage = `✅ Announcement sent successfully!\n\n`;
    summaryMessage += `• Target: ${target}\n`;
    summaryMessage += `• Successful deliveries: ${successCount}\n`;
    summaryMessage += `• Failed deliveries: ${failedCount}\n`;
    
    if (filteredRecipients.length === 0) {
      summaryMessage = `ℹ️ No recipients found for ${target} (excluding yourself).`;
    }

    ctx.reply(summaryMessage, adminMenu);

  } catch (error) {
    console.error('Error in send announcement scene:', error);
    ctx.reply('❌ An error occurred. Please try again.', adminMenu);
  } finally {
    ctx.scene.leave();
  }
});

// Handle unsupported media types
sendAnnouncementScene.on('message', (ctx) => {
  ctx.reply('❌ Unsupported message type. Please send text, photo, video, document, audio, or voice.');
});

stage.register(sendAnnouncementScene);

// Teacher Subject Registration Scene
const registerTeacherSubjectScene = new Scenes.BaseScene('register_teacher_subject_scene');
registerTeacherSubjectScene.enter((ctx) =>
    ctx.reply('🧑🏫 Please enter the subject you teach (e.g., Math, Science).')
);
registerTeacherSubjectScene.on('text', async (ctx) => {
    const subject = ctx.message.text.trim();
    if (!isValidSubject(subject)) {
        ctx.reply('❌ Invalid subject. Please enter a non-empty subject name (max 50 characters).');
        return;
    }
    try {
        const user = await getUserById(ctx.from.id);
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (user && teacher) {
            if (teacher.pendingSubjects && teacher.pendingSubjects.includes(subject)) {
                ctx.reply(`❌ "${subject}" is already pending verification.`);
                return ctx.scene.leave();
            }
            
            if (!teacher.pendingSubjects) teacher.pendingSubjects = [];
            teacher.pendingSubjects.push(subject);
            await teacher.save();
            
            const admins = await getAdmins();
            for (const admin of admins) {
                try {
                    ctx.telegram.sendMessage(admin.telegramId, `🔔 *New Subject Verification Request from ${teacher.name}:*
Subject: **${subject}**
Teacher ID: **${teacher.teacherId}**`, {
                        parse_mode: "HTML",
                        ...Markup.inlineKeyboard([
                            [Markup.button.callback('✅ Approve', `approve_subject_${teacher.teacherId}_${subject.replace(/ /g, '_')}`)],
                            [Markup.button.callback('❌ Deny', `deny_subject_${teacher.teacherId}_${subject.replace(/ /g, '_')}`)]
                        ])
                    });
                } catch (error) {
                    console.error(`Failed to notify admin ${admin.telegramId}:`, error);
                }
            }
            ctx.reply(`✅ Your request to add "${subject}" has been sent for admin verification.`, teacherMenu);
        } else {
            ctx.reply('❌ An error occurred. Please contact an admin.');
        }
    } catch (error) {
        console.error('Error in register teacher subject scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});
stage.register(registerTeacherSubjectScene);


// Contact Parent Scene
const contactParentScene = new Scenes.BaseScene('contact_parent_scene');
contactParentScene.enter((ctx) => ctx.reply('🆔 Please enter the student ID of the parent you want to contact.'));
contactParentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a 10-digit ID.');
        return ctx.scene.leave();
    }
    try {
        const student = await getStudentById(studentId);
        if (!student || !student.parentId) {
            return ctx.reply('❌ Student ID not found or student has no linked parent.');
        }
        ctx.session.recipientId = student.parentId;
        ctx.reply('📝 Please type the message you want to send to the parent.');
        ctx.scene.enter('send_message_scene');
    } catch (error) {
        console.error('Error in contact parent scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
        ctx.scene.leave();
    }
});
stage.register(contactParentScene);

const sendMessageScene = new Scenes.BaseScene('send_message_scene');
sendMessageScene.on('text', async (ctx) => {
    const message = ctx.message.text.trim();
    const recipientId = ctx.session.recipientId;
    if (!isValidAnnouncementOrMessage(message) || !recipientId) {
        ctx.reply('❌ Message cannot be empty or recipient not set.');
        return ctx.scene.leave();
    }
    try {
        const sender = await getUserById(ctx.from.id);
        const senderRole = sender.role === 'teacher' ? 'Teacher' : 'Admin';
        await ctx.telegram.sendMessage(recipientId, `📢 *Message from ${senderRole} (${sender.name}):*
${message}`, { parse_mode: 'HTML' });
        ctx.reply('✅ Message sent successfully.', teacherMenu);
    } catch (error) {
        if (error.response && error.response.error_code === 403) {
            ctx.reply('❌ Failed to send message. The recipient has blocked the bot.');
        } else {
            console.error(`Failed to send message:`, error);
            ctx.reply('❌ Failed to send message. Please try again later.');
        }
    } finally {
        ctx.session.recipientId = null;
        ctx.scene.leave();
    }
});
stage.register(sendMessageScene);


// Add Teacher Scene - Fixed for sparse index
const addTeacherScene = new Scenes.BaseScene('add_teacher_scene');
addTeacherScene.enter((ctx) => ctx.reply('📝 Please provide the teacher\'s full name.'));
addTeacherScene.on('text', async (ctx) => {
    const teacherName = ctx.message.text.trim();
    if (!isValidName(teacherName)) {
        ctx.reply('❌ Invalid name. Please provide a non-empty name (max 100 characters).');
        return;
    }
    try {
        const teacherId = await generateUniqueTeacherId();
        
        // Create teacher without telegramId field (not undefined or null)
        const newTeacher = new Teacher({
            teacherId,
            name: teacherName,
            // Do NOT include telegramId field for new teachers
            subjects: [],
            pendingSubjects: []
        });
        
        await newTeacher.save();
        
        ctx.replyWithHTML(
  `✅ Teacher "<b>${teacherName}</b>" added with unique ID: <b>${teacherId}</b>\n` +
  `<i>Share this ID with the teacher for registration.</i>`
);

    } catch (error) {
        console.error('Error in add teacher scene:', error);
        
        // Handle duplicate key error for telegramId
        if (error.code === 11000 && error.keyPattern && error.keyPattern.telegramId) {
            // Clean up existing null telegramId values
            try {
                await Teacher.updateMany(
                    { telegramId: null },
                    { $unset: { telegramId: 1 } }
                );
                ctx.reply('⚠️ Please try adding the teacher again.');
            } catch (fixError) {
                ctx.reply('❌ A system error occurred. Please contact an administrator.');
            }
        } else {
            ctx.reply('❌ An error occurred. Please try again.');
        }
    }
    
    ctx.scene.leave();
});

addTeacherScene.leave((ctx) => ctx.reply('⬅️ Returning to user management menu.', {
    reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
}));
stage.register(addTeacherScene);
// Add Subject Scene
const addSubjectScene = new Scenes.BaseScene('add_subject_scene');
addSubjectScene.enter((ctx) => ctx.reply('📚 Please enter the new subject you want to add. An admin will review your request.'));
addSubjectScene.on('text', async (ctx) => {
    const newSubject = ctx.message.text.trim();
    if (!isValidSubject(newSubject)) {
        ctx.reply('❌ Invalid subject. Please enter a non-empty subject name (max 50 characters).');
        return;
    }
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher) {
            return ctx.reply('❌ An error occurred. Please contact an admin.');
        }
        const subjects = teacher.subjects || [];
        const pendingSubjects = teacher.pendingSubjects || [];
        
        if (subjects.includes(newSubject) || pendingSubjects.includes(newSubject)) {
            return ctx.reply(`❌ "${newSubject}" is already one of your subjects or is pending verification.`);
        }
        
        if (!teacher.pendingSubjects) teacher.pendingSubjects = [];
        teacher.pendingSubjects.push(newSubject);
        await teacher.save();
        
        const admins = await getAdmins();
        for (const admin of admins) {
            try {
                await ctx.telegram.sendMessage(admin.telegramId, `🔔 *New Subject Verification Request from ${teacher.name}:*
Subject: **${newSubject}**
Teacher ID: **${teacher.teacherId}**`, {
                    parse_mode: 'HTML',
                    ...Markup.inlineKeyboard([
                        [Markup.button.callback('✅ Approve', `approve_subject_${teacher.teacherId}_${newSubject.replace(/ /g, '_')}`)],
                        [Markup.button.callback('❌ Deny', `deny_subject_${teacher.teacherId}_${newSubject.replace(/ /g, '_')}`)]
                    ])
                });
            } catch (error) {
                if (error.response && error.response.error_code === 403) {
                    console.log(`Admin ${admin.telegramId} has blocked the bot.`);
                } else {
                    console.error(`Failed to notify admin ${admin.telegramId}:`, error);
                }
            }
        }
        ctx.reply(`✅ Your request to add "${newSubject}" has been sent for admin verification.`, teacherMenu);
    } catch (error) {
        console.error('Error in add subject scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});
stage.register(addSubjectScene);

// Remove Subject Scene
const removeSubjectScene = new Scenes.BaseScene('remove_subject_scene');
removeSubjectScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects to remove.', teacherMenu);
            return ctx.scene.leave();
        }
        const subjectButtons = teacher.subjects.map(s => [Markup.button.callback(s, `remove_subject_${s.replace(/ /g, '_')}`)]);
        ctx.reply('📚 Please select the subject you want to remove:', Markup.inlineKeyboard(subjectButtons));
    } catch (error) {
        console.error('Error in remove subject scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
        ctx.scene.leave();
    }
});
stage.register(removeSubjectScene);


// Teacher Announcement Scene
const teacherAnnouncementScene = new Scenes.BaseScene('teacher_announcement_scene');
teacherAnnouncementScene.on('text', async (ctx) => {
    const announcement = ctx.message.text.trim();
    if (!isValidAnnouncementOrMessage(announcement)) {
        ctx.reply('❌ Announcement cannot be empty.');
        return;
    }
    try {
        const user = await getUserById(ctx.from.id);
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const subject = ctx.session.announcementSubject;
        if (!user || !teacher || !subject) {
            return ctx.reply('❌ An error occurred. Please contact an admin.');
        }
        
        // Find students who have grades in this subject
        const students = await Student.find({
            [`grades.${subject.toLowerCase()}`]: { $exists: true, $ne: [] }
        });
        
        const parentIds = [...new Set(students.map(s => s.parentId).filter(id => id !== null))];
        
        for (const parentId of parentIds) {
            try {
                await ctx.telegram.sendMessage(parentId, `📢 *Message from your child's ${subject} Teacher:*
${announcement}`, { parse_mode: "HTML" });
            } catch (error) {
                if (error.response && error.response.error_code === 403) {
                    console.log(`Parent ${parentId} has blocked the bot.`);
                } else {
                    console.error(`Failed to send announcement to parent ${parentId}:`, error);
                }
            }
        }
        ctx.reply('✅ Announcement sent to all parents of your students.', teacherMenu);
    } catch (error) {
        console.error('Error in teacher announcement scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});
stage.register(teacherAnnouncementScene);


// --- Menus ---

// Update the admin menu to include the Export IDs option
const adminMenu = Markup.keyboard([
  ['🧑🎓 Students', '👥 Users', '🚫 Ban/Unban Teacher'],
  ['✉️ Contact Teacher', '📞 Contact Parent', '👑 Contact Admins'],
  ['🔍 Search Database', '📁 Manage Uploads', '📤 Export IDs'],
  ['📢 Announcements']
]).resize();

const userManagementMenu = Markup.keyboard([
    ['✏️ Edit Teacher', '🗑️ Remove Teacher'],
    ['➕ Add Teacher'],
    ['📋View Admins', '📋 View Teachers', '📋 View Parents'],
    ['⬅️ Back to Admin Menu']
]).resize();

const studentManagementMenu = Markup.keyboard([
    ['➕ Add Student', '➖ Remove Student', '✏️ Edit Student'],
    ['📤 Upload Student List', '🔗 Unbind Parent', '🗑️ Delete Class'],
    ['📋 View All Students', '📋 View All Classes'],
    ['⬅️ Back to Admin Menu']
]).resize();

// --- Menu Definitions ---
const loginMenu = Markup.keyboard([
    ['👨‍🏫 Teacher Registration', '🔐 Teacher Login'],
    ['👤 Parent Registration'],
]).resize();

const parentMenu = Markup.keyboard([
    ['💯 View Grades', '📅 View Attendance', '👤 My Profile'],
    ['🔗 Unlink a Student', '🔗 Link Another Student']
]).resize();


// Master Admin Menu
const masterAdminMenu = Markup.keyboard([
    ['👑 View All Admins', '🚫 Remove Admin'],
    ['📊 Admin Activities', '🔍 Admin Details'],
    ['📝 Promote to Admin', '⬅️ Back to Main']
]).resize();

// Master admin command
bot.command('master', requireMasterAdmin, async (ctx) => {
    ctx.reply('👑 Master Admin Panel', masterAdminMenu);
});


//logout menu
const postLogoutMenu = Markup.keyboard([
  ['🔐 Login', '❓ Forgot Password']
]).resize();


// Update teacher menu to include logout
const teacherMenu = Markup.keyboard([
    ['📚 My Students', '➕ Add a Student', '🗑️ Remove Student'],
    ['📖 My Subjects', '📋 Request List', '🔍 Search Students'],   
    ['📝 Record Attendance', '📊 Manage Grades', '📤 Export Grades'],
    ['💬 Contact a Parent', '📢 Announce Parents', '👑 Contact Admin' ],
    ['🔓 Logout']  // Added logout button
]).resize();
const teacherProfileMenu = Markup.inlineKeyboard([
    [Markup.button.callback('➕ Add New Subject', 'add_new_subject'), Markup.button.callback('➖ Remove Subject', 'remove_subject')],
    [Markup.button.callback('⬅️ Back to Teacher Menu', 'back_to_teacher')]
]);

const parentProfileMenu = Markup.inlineKeyboard([
    [Markup.button.callback('🔗 Linked Students', 'view_linked_children')],
    [Markup.button.callback('⬅️ Back to Parent Menu', 'back_to_parent')]
]);





// --- Bot Commands ---

// Auto-initialize master admin on startup
const initializeMasterAdmin = async () => {
    try {
        const masterAdminId = process.env.MASTER_ADMIN_ID;
        if (!masterAdminId) {
            console.log('⚠️  MASTER_ADMIN_ID not set in environment');
            return;
        }

        let masterAdmin = await User.findOne({ telegramId: masterAdminId });
        
        if (!masterAdmin) {
            masterAdmin = new User({
                telegramId: masterAdminId,
                name: 'Master Admin',
                role: 'admin',
                masterAdmin: true
            });
            await masterAdmin.save();
            console.log('✅ Master admin initialized');
        } else if (!masterAdmin.masterAdmin) {
            masterAdmin.masterAdmin = true;
            masterAdmin.role = 'admin';
            await masterAdmin.save();
            console.log('✅ Existing user promoted to master admin');
        }
    } catch (error) {
        console.error('Error initializing master admin:', error);
    }
};

// Call this during bot startup
initializeMasterAdmin();
 
// --- ADD THIS START COMMAND HANDLER ---
// --- Bot Start ---
bot.start(async (ctx) => {
    try {
        const telegramId = ctx.from.id.toString();
        const masterAdminId = process.env.MASTER_ADMIN_ID;

        let user = await User.findOne({ telegramId });

        if (!user) {
            // First time: create base user
            user = new User({
                telegramId,
                username: ctx.from.username || '',
                name: ctx.from.first_name || 'User',
                role: 'user'
            });

            // Special case: Master Admin
            if (telegramId === masterAdminId) {
                user.role = 'masterAdmin';
                user.masterAdmin = true;
            }

            await user.save();
        } else {
            // Upgrade to master admin if needed
            if (telegramId === masterAdminId && !user.masterAdmin) {
                user.role = 'admin';
                user.masterAdmin = true;
                await user.save();
            }
        }

        // --- Role Detection ---
        const teacher = await Teacher.findOne({ telegramId });
        const parent = await User.findOne({ telegramId, role: 'parent' });

        if (user.masterAdmin) {
            // MASTER ADMIN gets direct access to master admin menu
            await ctx.replyWithHTML(
                `👑 Welcome, <b>${user.name}</b>!\n\n✅ You are logged in as <b>Master Admin</b>.`,
                masterAdminMenu // Master Admin menu
            );
        } else if (teacher) {
            user.role = 'teacher';
            await user.save();
            await ctx.replyWithHTML(
                `👨‍🏫 Welcome back, <b>${teacher.name}</b>!\n\nYou are logged in as <b>Teacher</b>.`,
                postLogoutMenu
            );
        } else if (parent) {
            user.role = 'parent';
            await user.save();
            await ctx.replyWithHTML(
                `👪 Welcome back, <b>${user.name}</b>!\n\nYou are logged in as <b>Parent</b>.`,
                parentMenu
            );
        } else {
            // Default: new/regular user
            await ctx.replyWithHTML(
                `👋 Welcome, <b>${user.name}</b>!\n\nPlease choose your role to continue:`,
                loginMenu
            );
        }

        // Track activity
        await trackAdminActivity(ctx, 'user_start', {
            role: user.role,
            masterAdmin: user.masterAdmin || false
        });

    } catch (error) {
        console.error('Error in /start:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
});










// Approve
bot.action(/link_yes_(\d+)_(.+)/, async (ctx) => {
    await ctx.answerCbQuery();
    const parentId = ctx.match[1];
    const studentId = ctx.match[2];

    const parent = await User.findOne({ telegramId: parentId, role: 'parent' });
    const student = await Student.findOne({ studentId });

    if (!parent || !student) {
        return ctx.reply('❌ Parent or student not found.');
    }

    // ✅ Enforce max 3 students per parent
    if (parent.studentIds.length >= 3) {
        await ctx.telegram.sendMessage(
            parentId,
            '❌ Linking denied. You can only link up to 3 students.',
            { parse_mode: "HTML" }
        );
        return ctx.reply('⚠️ Linking denied: Parent already has 3 linked students.');
    }

    // ✅ Update student
    student.parentId = parentId;
    student.pendingParentId = null;
    await student.save();

    // ✅ Update parent
    if (!parent.studentIds.includes(studentId)) {
        parent.studentIds.push(studentId);
    }
    parent.pendingStudentIds = parent.pendingStudentIds.filter(id => id !== studentId);
    await parent.save();

    // ✅ Notify parent and show menu
    await ctx.telegram.sendMessage(
        parentId,
        `✅ Your request to register as parent of *${student.name}* (${student.studentId}) was approved.\n\n` +
        `🎉 Welcome! You can now access the parent menu below 👇`,
        {
            parse_mode: "HTML",
            reply_markup: parentMenu.reply_markup   // 👈 send the parent menu directly
        }
    );

    // ✅ Notify admin
    ctx.reply(`✅ You approved linking ${student.name} (${student.studentId}) to ${parent.name}.`);
});

// Deny
bot.action(/link_no_(\d+)_(.+)/, async (ctx) => {
    await ctx.answerCbQuery();
    const parentId = ctx.match[1];
    const studentId = ctx.match[2];

    const parent = await User.findOne({ telegramId: parentId, role: 'parent' });
    const student = await Student.findOne({ studentId });

    if (student) {
        student.pendingParentId = null;   // clear pending parent
        await student.save();
    }

    if (parent) {
        parent.pendingStudentIds = parent.pendingStudentIds.filter(id => id !== studentId); // remove from pending list
        await parent.save();
    }

    if (parent) {
        await ctx.telegram.sendMessage(
            parentId,
            `❌ Your request to link *${student ? student.name : 'student'}* (${studentId}) was denied.`,
            { parse_mode: "HTML" }
        );
    }

    ctx.reply('❌ You denied the link request.');
});



// --- Main Menu Action Handlers ---



bot.action(/^approve_request_(.+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    const requestId = ctx.match[1];
    const StudentListRequest = mongoose.model('StudentListRequest');
    
    try {
        const request = await StudentListRequest.findById(requestId);
        if (!request || request.status !== 'pending') {
            return ctx.reply('❌ Request not found or already processed.');
        }

        // Fetch students of requested class
        const students = await Student.find({ class: request.className }).sort({ name: 1 });
        if (students.length === 0) {
            ctx.reply(`❌ No students found in class ${request.className}.`);
            return;
        }

        // Initialize progress tracking
        let processed = 0;
        const total = students.length;
        let messageIdAdmin = null;
        let messageIdTeacher = null;
        const startTime = Date.now();

        // Send initial progress message to admin
        const initialAdminMessage = await ctx.reply(
            `📋 Processing student list request for class ${request.className}...\n` +
            `Progress: 0/${total} (0%)\n` +
            `Status: Starting...`,
            { parse_mode: 'HTML' }
        );
        messageIdAdmin = initialAdminMessage.message_id;

        // Send initial progress message to teacher
        const initialTeacherMessage = await ctx.telegram.sendMessage(
            request.teacherTelegramId,
            `📋 Your student list request for class ${request.className} (subject: ${request.subject}) is being processed...\n` +
            `Progress: 0/${total} (0%)\n` +
            `Status: Starting...`,
            { parse_mode: 'HTML' }
        );
        messageIdTeacher = initialTeacherMessage.message_id;

        // Generate student ID file content
        let content = students.map(s => s.studentId).join('\n');

        // Add students to TeacherStudent collection with progress updates
        const teacher = await Teacher.findOne({ teacherId: request.teacherId });
        const teacherName = teacher ? teacher.name : "Teacher";
        for (const student of students) {
            try {
                // Check if relation exists
                const exists = await TeacherStudent.findOne({
                    teacherId: request.teacherId,
                    studentId: student.studentId,
                    subject: request.subject
                });
                if (!exists) {
                    const rel = new TeacherStudent({
                        teacherId: request.teacherId,
                        teacherName,
                        studentId: student.studentId,
                        studentName: student.name,
                        subject: request.subject,
                        className: request.className,
                        addedDate: new Date()
                    });
                    await rel.save();
                }
                processed++;

                // Calculate progress
                const percentage = Math.round((processed / total) * 100);
                const elapsedTime = (Date.now() - startTime) / 1000; // seconds
                const speed = processed / elapsedTime || 0; // students per second
                const eta = total > processed ? ((total - processed) / speed).toFixed(1) : 0;

                // Update admin message
                await ctx.telegram.editMessageText(
                    ctx.chat.id,
                    messageIdAdmin,
                    null,
                    `📋 Processing student list request for class ${request.className}...\n` +
                    `Progress: ${processed}/${total} (${percentage}%)\n` +
                    `Speed: ${speed.toFixed(2)} students/sec\n` +
                    `ETA: ${eta} seconds\n` +
                    `Status: Linking students...`,
                    { parse_mode: 'HTML' }
                );

                // Update teacher message
                await ctx.telegram.editMessageText(
                    request.teacherTelegramId,
                    messageIdTeacher,
                    null,
                    `📋 Your student list request for class ${request.className} (subject: ${request.subject}) is being processed...\n` +
                    `Progress: ${processed}/${total} (${percentage}%)\n` +
                    `Status: Linking students...`,
                    { parse_mode: 'HTML' }
                );

            } catch (error) {
                console.error(`Error processing student ${student.studentId}:`, error);
                // Continue processing other students
            }
        }

        // Save file temporarily
        const tempDir = './temp_exports';
        if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
        const fileName = `student_ids_${request.className.replace(/\s+/g, '_')}_${Date.now()}.txt`;
        const filePath = path.join(tempDir, fileName);
        fs.writeFileSync(filePath, content);

        // Update request status
        request.status = 'approved';
        request.approvalDate = new Date();
        request.approvedBy = ctx.from.id;
        await request.save();

        // Notify master admin with final statistics
        await notifyMasterAdmin(ctx, 'approve_student_list', {
            className: request.className,
            statistics: {
                processedStudents: processed,
                totalStudents: total
            },
            totalTime: ((Date.now() - startTime) / 1000).toFixed(1) + ' seconds'
        });

        // Send file to teacher
        try {
            await ctx.telegram.sendDocument(
                request.teacherTelegramId,
                { source: filePath, filename: fileName },
                { caption: `📋 Student IDs for class ${request.className} (${processed}/${total} students processed)` }
            );

            // Update final messages
            await ctx.telegram.editMessageText(
                ctx.chat.id,
                messageIdAdmin,
                null,
                `✅ Student list request for class ${request.className} approved!\n` +
                `Processed: ${processed}/${total} students\n` +
                `Time taken: ${((Date.now() - startTime) / 1000).toFixed(1)} seconds`,
                { parse_mode: 'HTML' }
            );

            await ctx.telegram.editMessageText(
                request.teacherTelegramId,
                messageIdTeacher,
                null,
                `✅ Your student list request for class ${request.className} (subject: ${request.subject}) has been approved!\n` +
                `Processed: ${processed}/${total} students\n` +
                `Check the document below for the student list.`,
                { parse_mode: 'HTML' }
            );
        } catch (error) {
            console.error('Failed to send student list to teacher:', error);
            await ctx.telegram.sendMessage(
                request.teacherTelegramId,
                `❌ Error sending student list for class ${request.className}. Please contact an admin.`
            );
            await ctx.telegram.editMessageText(
                ctx.chat.id,
                messageIdAdmin,
                null,
                `❌ Error sending student list to teacher for class ${request.className}.\n` +
                `Processed: ${processed}/${total} students`,
                { parse_mode: 'HTML' }
            );
        }

        // Clean up file
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    } catch (error) {
        console.error('Error approving request:', error);
        await ctx.reply('❌ An error occurred while processing the request.');
        await ctx.telegram.sendMessage(
            request.teacherTelegramId,
            `❌ Error processing your student list request for class ${request.className}. Please contact an admin.`
        );
    }
});


// Master Admin Menu Handlers
bot.hears('👑 View All Admins', requireMasterAdmin, (ctx) => {
    ctx.scene.enter('view_all_admins_scene');
});

bot.hears('🚫 Remove Admin', requireMasterAdmin, (ctx) => {
    ctx.scene.enter('remove_admin_scene');
});

bot.hears('📊 Admin Activities', requireMasterAdmin, (ctx) => {
    ctx.scene.enter('admin_activities_scene');
});

bot.hears('📝 Promote to Admin', requireMasterAdmin, (ctx) => {
    ctx.scene.enter('promote_to_admin_scene');
});

bot.hears('⬅️ Back to Main', requireMasterAdmin, (ctx) => {
    ctx.reply('Returning to main menu...', loginMenu);
});


bot.hears('🔗 Unlink a Student', (ctx) => {
    ctx.scene.enter('parent_unlink_scene');
});

bot.hears('👤 Parent Registration', async (ctx) => {
  ctx.scene.enter('register_parent_scene');
});

// Add to bot hears handlers, assuming parentMenu has '📅 View Attendance' button
bot.hears('📅 View Attendance', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'parent') {
        ctx.scene.enter('parent_view_attendance_scene');
    } else {
        ctx.reply('❌ You are not authorized to view attendance.');
    }
});
// Teacher attendance command
bot.hears('📝 Record Attendance', requireTeacherAuth, async (ctx) => {
    try {
        // Check if user is a teacher by checking the database directly
        const user = await User.findOne({ telegramId: ctx.from.id });
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!user || user.role !== 'teacher' || !teacher) {
            return ctx.reply('❌ Teacher access required. Please make sure you are registered as a teacher.', loginMenu);
        }
        
        ctx.scene.enter('teacher_attendance_scene');
    } catch (error) {
        console.error('Error checking teacher access:', error);
        ctx.reply('❌ An error occurred. Please try again.', loginMenu);
    }
});
// Add handler for the Delete Class button in the admin menu
bot.hears('🗑️ Delete Class', async (ctx) => {
    if (ctx.session.__scenes && ctx.session.__scenes.current) {
        return ctx.reply('Please finish your current operation first.');
    }
    ctx.scene.enter('delete_class_scene');
});
bot.hears('🚫 Ban/Unban Teacher', async (ctx) => {
  const user = await getUserById(ctx.from.id);
  if (!user || user.role !== 'admin') {
    return ctx.reply('❌ You are not authorized to use this feature.');
  }
  const teachers = await Teacher.find().sort({ name: 1 });
  if (teachers.length === 0) {
    return ctx.reply('No teachers found.');
  }

  const buttons = teachers.map(teacher => [
    Markup.button.callback(
      `${teacher.name} (${teacher.teacherId}) - ${teacher.banned ? 'Unban' : 'Ban'}`,
      `${teacher.banned ? 'unban' : 'ban'}_${teacher.teacherId}`
    )
  ]);

  buttons.push([Markup.button.callback('❌ Cancel', 'cancel_ban_unban')]);

  ctx.reply('Select a teacher to ban or unban:', Markup.inlineKeyboard(buttons));
});

// Handle ban/unban actions
bot.action(/^ban_(.+)$/, async (ctx) => {
  try {
    const teacherId = ctx.match[1];
    await ctx.answerCbQuery();
    
    const teacher = await Teacher.findOne({ teacherId });
    if (!teacher) {
      return ctx.reply('❌ Teacher not found.');
    }

    if (teacher.banned) {
      return ctx.reply(`⚠️ Teacher ${teacher.name} is already banned.`);
    }

    teacher.banned = true;
    await teacher.save();

    // Track the admin activity
    await trackAdminActivity(ctx, 'teacher_banned', {
      teacherId: teacher.teacherId,
      teacherName: teacher.name,
      adminId: ctx.from.id
    });

    // Notify master admin (if not self)
    if (ctx.from.id.toString() !== process.env.MASTER_ADMIN_ID) {
      await notifyMasterAdmin(ctx, 'teacher_banned', {
        teacherId: teacher.teacherId,
        teacherName: teacher.name,
        adminName: ctx.from.first_name || 'Admin'
      });
    }

    // Notify the teacher if they have a Telegram ID
    if (teacher.telegramId) {
      try {
        await ctx.telegram.sendMessage(
          teacher.telegramId,
          `⚠️ *Account Banned*\n\n` +
          `Your account has been banned from using the School System Bot.\n` +
          `📅 Date: ${new Date().toLocaleString()}\n` +
          `📧 For more information, contact the school administration.`,
          { parse_mode: 'HTML' }
        );
      } catch (error) {
        console.error(`Failed to notify teacher ${teacherId} of ban:`, error);
        // Fallback: Log to activity log for manual follow-up
        await trackAdminActivity(ctx, 'teacher_notification_failed', {
          teacherId: teacher.teacherId,
          action: 'ban',
          error: error.message
        });
      }
    } else {
      // Log if teacher has no Telegram ID for manual follow-up
      await trackAdminActivity(ctx, 'teacher_no_telegram_id', {
        teacherId: teacher.teacherId,
        action: 'ban',
        message: 'Teacher has no Telegram ID for ban notification'
      });
    }

    ctx.reply(`✅ Teacher ${teacher.name} (${teacherId}) has been banned from accessing the bot.`);

  } catch (error) {
    console.error('Error banning teacher:', error);
    ctx.reply('❌ An error occurred while banning the teacher.');
  }
});

bot.action(/^unban_(.+)$/, async (ctx) => {
  try {
    const teacherId = ctx.match[1];
    await ctx.answerCbQuery();
    
    const teacher = await Teacher.findOne({ teacherId });
    if (!teacher) {
      return ctx.reply('❌ Teacher not found.');
    }

    if (!teacher.banned) {
      return ctx.reply(`⚠️ Teacher ${teacher.name} is not banned.`);
    }

    teacher.banned = false;
    await teacher.save();

    // Track the admin activity
    await trackAdminActivity(ctx, 'teacher_unbanned', {
      teacherId: teacher.teacherId,
      teacherName: teacher.name,
      adminId: ctx.from.id
    });

    // Notify master admin (if not self)
    if (ctx.from.id.toString() !== process.env.MASTER_ADMIN_ID) {
      await notifyMasterAdmin(ctx, 'teacher_unbanned', {
        teacherId: teacher.teacherId,
        teacherName: teacher.name,
        adminName: ctx.from.first_name || 'Admin'
      });
    }

    // Notify the teacher if they have a Telegram ID
    if (teacher.telegramId) {
      try {
        await ctx.telegram.sendMessage(
          teacher.telegramId,
          `✅ *Account Unbanned*\n\n` +
          `Your account has been unbanned. You can now access the School System Bot again.\n` +
          `📅 Date: ${new Date().toLocaleString()}\n` +
          `🎉 Welcome back! Use /start to access the bot.`,
          { parse_mode: 'HTML' }
        );
      } catch (error) {
        console.error(`Failed to notify teacher ${teacherId} of unban:`, error);
        // Fallback: Log to activity log for manual follow-up
        await trackAdminActivity(ctx, 'teacher_notification_failed', {
          teacherId: teacher.teacherId,
          action: 'unban',
          error: error.message
        });
      }
    } else {
      // Log if teacher has no Telegram ID for manual follow-up
      await trackAdminActivity(ctx, 'teacher_no_telegram_id', {
        teacherId: teacher.teacherId,
        action: 'unban',
        message: 'Teacher has no Telegram ID for unban notification'
      });
    }

    ctx.reply(`✅ Teacher ${teacher.name} (${teacherId}) has been unbanned and can now access the bot.`);

  } catch (error) {
    console.error('Error unbanning teacher:', error);
    ctx.reply('❌ An error occurred while unbanning the teacher.');
  }
});

bot.action('cancel_ban_unban', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.reply('Ban/unban operation cancelled.', adminMenu);
});

bot.action('teacher_register', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('teacher_register_start_scene');
});

bot.action('teacher_login', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('teacher_login_scene');
});

bot.action('cancel_operation', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('Operation cancelled.', Markup.removeKeyboard());
});

// Handle text commands for teacher registration and login
bot.hears('👨‍🏫 Teacher Registration', async (ctx) => {
    ctx.scene.enter('teacher_register_start_scene');
});

bot.hears('🔐 Teacher Login', async (ctx) => {
    ctx.scene.enter('teacher_login_scene');
});


bot.hears('📋 Request List', async (ctx) => {
  const user = await getUserById(ctx.from.id); // Retrieve user info to check role
  if (user && user.role === 'teacher') {
    if (ctx.scene && ctx.scene.session) {
      await ctx.scene.leave(); // Reset previous scene state if any
    }
    await ctx.scene.enter('request_students_list_scene'); // Enter the scene
  } else {
    await ctx.reply('❌ You are not authorized to use this feature.');
  }
});

// Handle logout command
bot.hears('🚪 Logout', async (ctx) => {
    // Clear session data
    ctx.session = null;
    ctx.reply('✅ Successfully logged out. Please log in again to access teacher features.', postLogoutMenu);
});
// Help command
bot.hears('ℹ️ Help', (ctx) => {
    ctx.reply(
        '🤖 School System Bot Help\n\n' +
        '• Register as Teacher: Start the teacher registration process\n' +
        '• Teacher Login: Log in to your teacher account\n' +
        '• Contact Admin: Get assistance from administrators\n\n' +
        'For technical issues, please contact the system administrator.'
    );
});
// Handle unknown callback queries


// Handle unhandled actions
bot.catch((err, ctx) => {
    console.error('Bot error:', err);
    ctx.reply('❌ An error occurred. Please try again.');
});
bot.command('admin', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        return ctx.reply('⚙️ Admin Panel', adminMenu);
    }
    ctx.scene.enter('admin_login_scene');
});



// --- Text/Keyboard Handlers ---


// --- Parent Profile Handler ---
bot.hears('👤 My Profile', async (ctx) => {
    try {
        // Get parent user
        const parent = await User.findOne({ telegramId: ctx.from.id, role: 'parent' });
        if (!parent) {
            return ctx.reply('❌ You are not registered as a parent.');
        }

        // Get students under this parent
        const students = await Student.find({ parentId: parent.telegramId });

        let message = `👨‍👩‍👧 *Parent Profile*\n━━━━━━━━━━━━━━━━━━━━\n`;
        message += `👤 *Name:* ${parent.name}\n`;
        if (ctx.from.username) {
            message += `📱 *Username:* @${ctx.from.username}\n`;
        }
        message += `🆔 *Telegram ID:* ${ctx.from.id}\n`;
        message += `🎭 *Role:* Parent\n\n`;

        if (students.length === 0) {
            message += `👶 *No students registered under this parent.*`;
        } else {
            message += `👨‍🎓 *Students Registered:*\n`;
            students.forEach((student, i) => {
                message += `\n${i + 1}. ${student.name}\n`;
                message += `   🆔 ID: ${student.studentId}\n`;
                message += `   🏫 Class: ${student.class}\n`;
            });
        }

        ctx.replyWithHTML(message);

    } catch (err) {
        console.error('Error showing parent profile:', err);
        ctx.reply('❌ Failed to load profile. Please try again later.');
    }
});


// Handle Forgot Password menu button
bot.hears('❓ Forgot Password', (ctx) => {
  ctx.scene.enter('teacher_forgot_password_scene');
});
// Teacher Logout Handler - Fixed to maintain proper state
bot.hears('🔓 Logout', async (ctx) => {
  try {
    // Remove Telegram link safely
    await Teacher.updateOne(
      { telegramId: ctx.from.id },
      { $unset: { telegramId: "" } }
    );

    // If you have user/admin updates
    await User.updateOne(
      { adminId: ctx.from.id },
      { $unset: { adminId: "" } }
    );

    // Send message with a new keyboard having only the login button for teachers
    await ctx.reply('✅ You have been logged out.', postLogoutMenu);
  } catch (err) {
    console.error("Logout error:", err);
    await ctx.reply("Something went wrong during logout.");
  }
});
bot.hears('🔐 Login', async (ctx) => {
  ctx.scene.enter('teacher_login_scene'); // or the scene handling teacher login
});



// Add handler for the new menu option
bot.hears('👑 Contact Admin', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_contact_admin_scene');
    } else {
        ctx.reply('❌ You are not authorized to contact admins.');
    }
});
// Add handler for the new menu option
bot.hears('📤 Export Grades', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_export_grades_scene');
    } else {
        ctx.reply('❌ You are not authorized to export grades.');
    }
});
// Add handler for the new menu option
bot.hears('🔍 Search Students', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_search_student_scene');
    } else {
        ctx.reply('❌ You are not authorized to search students.');
    }
});
// Add handler for the new menu option
bot.hears('💬 Contact a Parent', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_contact_parent_scene');
    } else {
        ctx.reply('❌ You are not authorized to contact parents.');
    }
});
// Add handler for the new menu option
bot.hears('🗑️ Remove Student', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_remove_student_scene');
    } else {
        ctx.reply('❌ You are not authorized to remove students.');
    }
});
// Add handler for the new menu option
bot.hears('📢 Announce Parents', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('announce_class_scene');
    } else {
        ctx.reply('❌ You are not authorized to send announcements.');
    }
});
// Add handler for the new menu option
bot.hears('📖 My Subjects', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_my_subjects_scene');
    } else {
        ctx.reply('❌ You are not authorized to manage subjects.');
    }
});
bot.hears('📊 Manage Grades', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('manage_grades_scene');
    } else {
        ctx.reply('❌ You are not authorized to manage grades.');
    }
});
bot.hears('📋 Upload Student List', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_upload_students_scene');
    } else {
        ctx.reply('❌ You are not authorized to upload student lists.');
    }
});
// Contact Admins menu handler
bot.hears('👑 Contact Admins', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('contact_admins_scene');
    } else {
        ctx.reply('❌ You are not authorized to contact admins.');
    }
});
bot.hears('📞 Contact Parent', async (ctx) => {
  const user = await getUserById(ctx.from.id);
  if (user && user.role === 'admin') {
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('contact_parent_admin_scene');
  } else {
    ctx.reply('❌ You are not authorized to contact parents.');
  }
});
bot.hears('✉️ Contact Teacher', async (ctx) => {
  const user = await getUserById(ctx.from.id);
  if (user && user.role === 'admin') {
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('contact_teacher_scene');
  } else {
    ctx.reply('❌ You are not authorized to contact teachers.');
  }
});

bot.hears('🗑️ Remove Teacher', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('remove_teacher_scene');
    } else {
        ctx.reply('❌ You are not authorized to remove teachers.');
    }
});
// Export IDs menu handler
bot.hears('📤 Export IDs', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('export_ids_scene');
    } else {
        ctx.reply('❌ You are not authorized to use this feature.');
    }
});

bot.hears('📋 View All Classes', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        const availableClasses = await getUniqueClasses();
        
        if (availableClasses.length === 0) {
            ctx.reply('No classes found. Please upload a student list first.');
            return;
        }
        
        const classList = availableClasses.map((className, index) => 
            `${index + 1}. ${className}`
        ).join('\n');
        
        ctx.reply(`📚 Available Classes:\n\n${classList}`);
    }
});
bot.hears('🧑🎓 Students', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        ctx.reply('🧑‍🎓 Student Management:', studentManagementMenu);
    }
});

bot.hears('👥 Users', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        ctx.reply('👥 User Management:', userManagementMenu);
    }
});

bot.hears('📢 Announcements', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        ctx.scene.enter('announcement_recipient_scene');
    } else {
        ctx.reply('❌ You do not have permission to send announcements.');
    }
});

bot.hears('🔍 Search Database', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && (user.role === 'admin')) {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('admin_search_scene');
    } else {
        ctx.reply('❌ You are not authorized to use this feature.');
    }
});

bot.hears('📁 Manage Uploads', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        try {
            const uploadedFiles = await UploadedFile.find();
            if (uploadedFiles.length === 0) {
                ctx.reply('📂 No files have been uploaded yet.');
                return;
            }
            let fileList = '*Uploaded Files:*';
            uploadedFiles.forEach(file => {
                const status = file.processed ? '✅ Processed' : '⏳ Pending';
                const classInfo = file.classAssigned ? ` (Class: ${file.classAssigned})` : '';
                fileList += `• *${file.originalName}*
  ID: ${file.id}
  Upload Date: ${new Date(file.uploadDate).toLocaleString()}
  Status: ${status}${classInfo}
`;
            });
            const deleteButtons = uploadedFiles.map(file =>
                [Markup.button.callback(`🗑️ Delete ${file.originalName}`, `delete_file_${file.id}`)]
            );
            ctx.replyWithHTML(fileList, Markup.inlineKeyboard(deleteButtons));
        } catch (error) {
            console.error('Error managing uploads:', error);
            ctx.reply('❌ An error occurred while retrieving uploaded files.');
        }
    } else {
        ctx.reply('❌ You are not authorized to manage uploads.');
    }
});


bot.hears('➕ Add Teacher', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('add_teacher_scene');
    }
});


// Edit Teacher menu handler
bot.hears('✏️ Edit Teacher', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('edit_teacher_scene');
    }
});

bot.hears('📋View Admins', async (ctx) => {
    try {
        const admins = await getAdmins();
        if (admins.length > 0) {
            const adminList = admins.map(u => `ID: ${u.telegramId}, Name: ${u.name}`).join('');
            ctx.replyWithHTML(`**Current Admins:**
${adminList}`);
        } else {
            ctx.reply('No admins found.');
        }
    } catch (error) {
        console.error('Error viewing admins:', error);
        ctx.reply('❌ An error occurred while retrieving admins.');
    }
});

bot.hears('📋 View Teachers', async (ctx) => {
  try {
    const teachers = await Teacher.find();
    if (teachers.length === 0) {
      return ctx.reply('No teachers found.');
    }

    let message = '**All Teachers:**\n\n';
    teachers.forEach(t => {
      const subjects = t.subjects.length > 0 ? t.subjects.join(', ') : 'N/A';
      const telegramId = t.telegramId || 'N/A';
      message += `• ID: ${t.teacherId}\n  Name: ${t.name}\n  Subjects: ${subjects}\n  Telegram ID: ${telegramId}\n\n`;
    });

    ctx.replyWithHTML(message);
  } catch (error) {
    console.error('Error viewing teachers:', error);
    ctx.reply('❌ An error occurred while retrieving teachers.');
  }
});


bot.hears('📋 View Parents', async (ctx) => {
  try {
    const parents = await User.find({ role: 'parent' });
    if (parents.length === 0) {
      return ctx.reply('No parents found.');
    }

    let content = `Parents List - Total: ${parents.length}\n\n`;
    content += 'Telegram ID | Name | Linked Students Count\n';
    content += '--------------------------------------\n';
    parents.forEach(p => {
      const linkedCount = p.studentIds ? p.studentIds.length : 0;
      content += `${p.telegramId} | ${p.name} | ${linkedCount}\n`;
    });

    const fs = require('fs');
    const path = require('path');
    const tempDir = './temp_exports';
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    const filePath = path.join(tempDir, `parents_list_${Date.now()}.txt`);
    fs.writeFileSync(filePath, content);

    await ctx.replyWithDocument({ source: filePath, filename: 'parents_list.txt' }, { caption: `📋 Detailed list of parents (${parents.length} total)` });

    // Clean up the file after sending
    fs.unlinkSync(filePath);

  } catch (error) {
    console.error('Error viewing parents:', error);
    ctx.reply('❌ An error occurred while retrieving parents.');
  }
});


bot.hears('🔗 Unbind Parent', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('unbind_parent_scene');
    }
});

bot.hears('➕ Add Student', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('add_student_scene');
    }
});

bot.hears('➖ Remove Student', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('remove_student_scene');
    }
});

bot.hears('✏️ Edit Student', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('edit_student_scene');
    }
});

bot.hears('📤 Upload Student List', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('upload_student_list_scene');
    }
});

// View All Students menu handler
bot.hears('📋 View All Students', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('view_students_by_grade_scene');
    } else {
        ctx.reply('❌ You are not authorized to use this feature.');
    }
});
bot.hears('⬅️ Back to Admin Menu', (ctx) => {
    ctx.reply('⬅️ Returning to admin menu.', adminMenu);
});

   bot.hears('💯 View Grades', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'parent') {
        if (ctx.scene?.session) ctx.scene.leave();
        try {
            const students = await getStudentsByParentId(user.telegramId);
            if (students.length === 0) {
                return ctx.reply('❌ You are not linked to any students.');
            }
            
            let fullGradeList = '📋 *Your Child(ren)\'s Grades:*\n\n';
            
            for (const student of students) {
                const result = await viewStudentGrades(student.studentId);
                if (!result) continue;
                
                fullGradeList += `--- *${student.name}* (Class: ${student.class || 'N/A'}) ---\n`;
                
                if (result.grades.length === 0) {
                    fullGradeList += 'No grades found.\n\n';
                } else {
                    // Group grades by subject
                    const gradesBySubject = {};
                    result.grades.forEach(grade => {
                        if (!gradesBySubject[grade.subject]) {
                            gradesBySubject[grade.subject] = [];
                        }
                        gradesBySubject[grade.subject].push(grade);
                    });
                    
                    for (const [subject, subjectGrades] of Object.entries(gradesBySubject)) {
                        fullGradeList += `*${subject}:*\n`;
                        subjectGrades.forEach(gradeInfo => {
                            fullGradeList += ` - Score: ${gradeInfo.score}, Purpose: ${gradeInfo.purpose}, Date: ${new Date(gradeInfo.date).toLocaleDateString()}\n`;
                        });
                        fullGradeList += '\n';
                    }
                }
            }
            
            return ctx.replyWithHTML(fullGradeList);
        } catch (error) {
            console.error('Error viewing grades:', error);
            ctx.reply('❌ An error occurred while retrieving grades.');
        }
    } else {
        ctx.reply('❌ You are not authorized to view grades.');
    }
});



bot.hears('🔗 Link Another Student', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'parent') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('link_another_student_scene');
    } else {
        ctx.reply('❌ You must be a parent to link students.');
    }
});

// Update the teacher menu handlers

// Add handler for the new menu option
bot.hears('➕ Add a Student', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_add_student_scene');
    } else {
        ctx.reply('❌ You are not authorized to add students.');
    }
});
bot.hears('📚 My Students', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_my_students_scene');
    } else {
        ctx.reply('❌ You are not authorized to manage students.');
    }
});

bot.hears('💬 Contact Parent', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('contact_parent_scene');
    } else {
        ctx.reply('❌ You are not authorized to contact parents.');
    }
});


// --- Action Handlers ---


bot.action('teacher_forgot_password', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.scene.enter('teacher_forgot_password_scene');
});

// Admin command to resend OTP
bot.action(/^resend_otp_(\d+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    const telegramId = ctx.match[1];
    
    const otpRecord = await OTP.findOne({ telegramId });
    if (!otpRecord) {
        ctx.reply('❌ No pending registration found for this user.');
        return;
    }
    
    // Generate new OTP
    const newOTP = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    
    otpRecord.otp = newOTP;
    otpRecord.expiresAt = expiresAt;
    otpRecord.attempts = 0;
    otpRecord.verified = false;
    await otpRecord.save();
    
    ctx.reply(
        `🔐 New OTP generated for user ${telegramId}:\n\n` +
        `OTP: ${newOTP}\n` +
        `Expires: ${expiresAt.toLocaleTimeString()}`
    );
    
    // Edit original message to show new OTP
    try {
        await ctx.editMessageText(
            ctx.update.callback_query.message.text + `\n\n🔄 OTP Resent: ${newOTP}`,
            { parse_mode: "HTML" }
        );
    } catch (error) {
        console.error('Error editing message:', error);
    }
});

// Admin command to cancel registration
bot.action(/^cancel_registration_(\d+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    const telegramId = ctx.match[1];
    
    await OTP.deleteOne({ telegramId });
    ctx.reply(`✅ Registration cancelled for user ${telegramId}.`);
    
    // Edit original message
    try {
        await ctx.editMessageText(
            ctx.update.callback_query.message.text + '\n\n❌ Registration Cancelled',
            { parse_mode: "HTML" }
        );
    } catch (error) {
        console.error('Error editing message:', error);
    }
});
// Helper function to view grades

bot.action('teacher_my_subjects', async (ctx) => {
    await ctx.answerCbQuery(); // Acknowledge the button click
    try {
        // Ensure any previous scene is left
        if (ctx.scene?.session) ctx.scene.leave();

        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        if (!teacher) {
            return ctx.reply('❌ Teacher record not found. Please contact an admin.');
        }

        // Display the subjects list scene
        await ctx.scene.enter('teacher_my_subjects_scene');

    } catch (error) {
        console.error('Error handling teacher_my_subjects action:', error);
        await ctx.reply('❌ An error occurred. Please try again.');
    }
});


bot.action('register_parent', async (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('register_parent_scene');
});

bot.action(/^announce_subject_(.+)$/, (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    ctx.session.announcementSubject = subject;
    ctx.answerCbQuery();
    ctx.reply(`📢 Please type the announcement to send to the parents of your students in ${subject}.`);
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('teacher_announcement_scene');
});

bot.action(/^manage_grades_(\d+)$/, (ctx) => {
    const studentId = ctx.match[1];
    ctx.session.currentStudentId = studentId;
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('manage_grades_scene');
});

bot.action('view_linked_children', async (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    try {
        const parent = await User.findOne({ telegramId: ctx.from.id, role: 'parent' });
        if (parent) {
            const studentIds = parent.studentIds || [];
            if (studentIds.length === 0) {
                return ctx.reply('You are not linked to any students.');
            }
            const students = await Promise.all(studentIds.map(id => getStudentById(id)));
            const validStudents = students.filter(s => s);
            if (validStudents.length === 0) {
                return ctx.reply('You are not linked to any valid students.');
            }
            const studentList = validStudents.map(s => `• Name: ${s.name}, ID: ${s.studentId}, Class: ${s.class || 'N/A'}`).join('');
            ctx.replyWithHTML(`**Linked Students:**
${studentList}`);
        } else {
            ctx.reply('❌ Your profile could not be found.');
        }
    } catch (error) {
        console.error('Error viewing linked children:', error);
        ctx.reply('❌ An error occurred while retrieving your linked students.');
    }
});

bot.action('add_new_subject', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('add_subject_scene');
});

bot.action('remove_subject', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('remove_subject_scene');
});

bot.action('teacher_add_student', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('teacher_add_student_scene');
});

bot.action('teacher_remove_student', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('teacher_remove_student_scene');
});

bot.action('back_to_teacher', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.reply('⬅️ Returning to teacher menu.', teacherMenu);
});

bot.action('back_to_parent', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.reply('⬅️ Returning to parent menu.', parentMenu);
});

// Update the action handlers in your main bot code
bot.action('edit_student_name', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_student_name_scene');
});

bot.action('edit_student_class', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_student_class_scene'); // Changed to new scene
});

// Action handler for edit student parent
bot.action('edit_student_parent', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_student_parent_scene');
});
// Action handlers for edit teacher options
bot.action('edit_teacher_name', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_teacher_name_scene');
});

bot.action('edit_teacher_subjects', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_teacher_subjects_scene');
});
bot.action('edit_teacher_telegram', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_teacher_telegram_scene');
});

bot.action(/^remove_subject_(.+)$/, async (ctx) => {
    const subjectToRemove = ctx.match[1].replace(/_/g, ' ');
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (teacher) {
            teacher.subjects = teacher.subjects.filter(s => s !== subjectToRemove);
            await teacher.save();
            
            const user = await getUserById(teacher.telegramId);
            if (user) {
                user.subjects = user.subjects.filter(s => s !== subjectToRemove);
                await user.save();
            }
            ctx.reply(`✅ Subject "${subjectToRemove}" has been removed from your profile.`, teacherMenu);
        } else {
            ctx.reply('❌ An error occurred. Subject not found.', teacherMenu);
        }
    } catch (error) {
        console.error('Error removing subject:', error);
        ctx.reply('❌ An error occurred while removing the subject.', teacherMenu);
    }
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
});

bot.action(/^approve_subject_(TE\d+)_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    try {
        const teacher = await getTeacherById(teacherId);
        if (teacher && teacher.pendingSubjects && teacher.pendingSubjects.includes(subject)) {
            teacher.subjects.push(subject);
            teacher.pendingSubjects = teacher.pendingSubjects.filter(s => s !== subject);
            await teacher.save();
            
            const user = await getUserById(teacher.telegramId);
            if (user) {
                user.subjects.push(subject);
                await user.save();
                ctx.replyWithHTML(`✅ Subject **${subject}** has been approved for **${teacher.name}**.`);
                try {
                    ctx.telegram.sendMessage(user.telegramId, `✅ Your request to add subject "${subject}" has been approved by an admin!`);
                } catch (e) { /* ignore */ }
            }
        } else {
            ctx.reply('❌ Request not found.');
        }
    } catch (error) {
        console.error('Error approving subject:', error);
        ctx.reply('❌ An error occurred while approving the subject.');
    }
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
});

bot.action(/^deny_subject_(TE\d+)_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    try {
        const teacher = await getTeacherById(teacherId);
        if (teacher && teacher.pendingSubjects && teacher.pendingSubjects.includes(subject)) {
            teacher.pendingSubjects = teacher.pendingSubjects.filter(s => s !== subject);
            await teacher.save();
            
            const user = await getUserById(teacher.telegramId);
            ctx.replyWithHTML(`❌ Subject **${subject}** has been denied for **${teacher.name}**.`);
            try {
                ctx.telegram.sendMessage(user.telegramId, `❌ Your request to add subject "${subject}" has been denied by an admin.`);
            } catch (e) { /* ignore */ }
        } else {
            ctx.reply('❌ Request not found.');
        }
    } catch (error) {
        console.error('Error denying subject:', error);
        ctx.reply('❌ An error occurred while denying the subject.');
    }
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
});

// Admin approval handler for parent requests
bot.action(/^approve_parent_(\d+)_(.+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    
    const parentId = ctx.match[1];
    const studentId = ctx.match[2];
    
    try {
        const parent = await getUserById(parentId);
        const student = await getStudentById(studentId);
        
        if (!parent || !student) {
            return ctx.reply('❌ Parent or student not found.');
        }
        
        // Update parent role and student list
        parent.role = 'parent';
        if (!parent.studentIds) parent.studentIds = [];
        if (!parent.studentIds.includes(studentId)) {
            parent.studentIds.push(studentId);
        }
        parent.pendingStudentIds = parent.pendingStudentIds.filter(id => id !== studentId);
        await parent.save();
        
        // Update student record
        student.parentId = parentId;
        student.pendingParentId = null;
        await student.save();
        
        // Notify parent
        try {
            await ctx.telegram.sendMessage(
                parentId,
                `✅ *Parent Registration Approved!*\n\n` +
                `You are now linked to student:\n` +
                `• Name: ${student.name}\n` +
                `• ID: ${student.studentId}\n` +
                `• Class: ${student.class}\n\n` +
                `You can now access their grades and school information.`,
                { parse_mode: "HTML" }
            );
        } catch (error) {
            console.error(`Failed to notify parent ${parentId}:`, error);
        }
        
        // Update admin message
        await ctx.editMessageText(
            `✅ Approved: ${parent.name} → ${student.name}\n` +
            `Parent can now access student information.`,
            { reply_markup: { inline_keyboard: [] } }
        );
        
    } catch (error) {
        console.error('Error approving parent:', error);
        ctx.reply('❌ An error occurred while approving the parent.');
    }
});

// Admin denial handler for parent requests
bot.action(/^deny_parent_(\d+)_(.+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    
    const parentId = ctx.match[1];
    const studentId = ctx.match[2];
    
    try {
        const parent = await getUserById(parentId);
        const student = await getStudentById(studentId);
        
        if (parent) {
            parent.pendingStudentIds = parent.pendingStudentIds.filter(id => id !== studentId);
            await parent.save();
        }
        
        if (student) {
            student.pendingParentId = null;
            await student.save();
        }
        
        // Notify parent
        try {
            await ctx.telegram.sendMessage(
                parentId,
                `❌ *Parent Registration Denied*\n\n` +
                `Your request to link with student ${studentId} has been denied by an administrator.\n` +
                `Please contact the school administration for more information.`
            );
        } catch (error) {
            console.error(`Failed to notify parent ${parentId}:`, error);
        }
        
        // Update admin message
        await ctx.editMessageText(
            `❌ Denied: Parent request for student ${studentId}\n` +
            `Parent has been notified.`,
            { reply_markup: { inline_keyboard: [] } }
        );
        
    } catch (error) {
        console.error('Error denying parent:', error);
        ctx.reply('❌ An error occurred while denying the parent.');
    }
});

bot.action(/^deny_parent_(\d+)_(\d+)$/, async (ctx) => {
    const parentIdStr = ctx.match[1];
    const studentId = ctx.match[2];
    const parentId = parentIdStr;
    
    if (!isValidTelegramId(parentIdStr) || !isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid request data.');
        ctx.answerCbQuery();
        return;
    }
    
    try {
        const parent = await getUserById(parentId);
        const student = await getStudentById(studentId);
        
        if (parent && student && student.pendingParentId === parentId) {
            student.pendingParentId = null;
            await student.save();
            
            if (parent.pendingStudentIds) {
                parent.pendingStudentIds = parent.pendingStudentIds.filter(id => id !== studentId);
            }
            if (parent.studentIds && parent.studentIds.length === 0 && 
                parent.pendingStudentIds && parent.pendingStudentIds.length === 0) {
                parent.role = 'user';
            }
            await parent.save();
            
            ctx.replyWithHTML(`❌ Parent ${parent.name} link request for student ${student.name} has been denied.`);
            try {
                ctx.telegram.sendMessage(parentId, `❌ Your request to link with student ${student.name} (ID: ${studentId}) has been denied.`);
            } catch (e) { /* ignore */ }
        } else {
            ctx.reply('❌ Request not found or already processed.');
        }
    } catch (error) {
        console.error('Error denying parent:', error);
        ctx.reply('❌ An error occurred while denying the parent request.');
    }
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
});

// Confirmation timeout in milliseconds
const CONFIRM_TIMEOUT_MS = 60 * 1000; // 60 seconds

// When admin clicks delete -> ask to type CONFIRM
bot.action(/^delete_file_(.+)$/, async (ctx) => {
  const fileIdToDelete = ctx.match[1];
  await ctx.answerCbQuery();

  const user = await getUserById(ctx.from.id);
  if (!user || (user.role !== 'admin' && !user.masterAdmin)) {
    return ctx.reply('❌ You are not authorized to delete files.');
  }

  // initialize map if missing
  ctx.session.pendingDeletes = ctx.session.pendingDeletes || {};

  // store pending request for this user only
  ctx.session.pendingDeletes[ctx.from.id] = {
    fileId: fileIdToDelete,
    expiresAt: Date.now() + CONFIRM_TIMEOUT_MS
  };

  await ctx.reply(
    `⚠️ Are you sure you want to delete this file?\n\n` +
    `🆔 File ID: ${fileIdToDelete}\n\n` +
    `👉 Type CONFIRM within ${Math.floor(CONFIRM_TIMEOUT_MS/1000)} seconds to delete.\n` +
    `👉 Type anything else to cancel.`
  );
});

// Global text handler that checks pending delete requests per-user
bot.on('text', async (ctx, next) => {
  const pendingMap = ctx.session.pendingDeletes;
  if (!pendingMap) return next();

  const pending = pendingMap[ctx.from.id];
  if (!pending) return next();

  // Clear pending immediately to avoid double-processing
  delete pendingMap[ctx.from.id];

  // Timeout check
  if (Date.now() > pending.expiresAt) {
    await ctx.reply('⏰ Deletion timed out. Cancelled.');
    return;
  }

  const input = ctx.message.text.trim().toUpperCase();
  const fileId = pending.fileId;

  if (input === 'CONFIRM') {
    // Re-check authorization (in case role changed)
    const user = await getUserById(ctx.from.id);
    if (!user || (user.role !== 'admin' && !user.masterAdmin)) {
      await ctx.reply('❌ You are not authorized to perform this action.');
      return;
    }

    try {
      const result = await UploadedFile.deleteOne({ id: fileId });
      if (result.deletedCount > 0) {
        await ctx.reply('🗑️ File deleted successfully.');

        // Log the deletion as admin DB-modifying action
        await trackAdminActivity(ctx, 'remove_uploaded_list', {
          removedFileId: fileId
        });

        // Optional extra DB change log
        await trackAdminActivity(ctx, 'modify_database', {
          model: 'UploadedFile',
          operation: 'deleteOne',
          targetId: fileId
        });
      } else {
        await ctx.reply('❌ File not found.');
      }
    } catch (error) {
      console.error('Error deleting file:', error);
      await ctx.reply('❌ An error occurred while deleting the file.');
    }
  } else {
    await ctx.reply('❌ Deletion cancelled.');
  }
});

// --- Launch bot ---
// Run migration first, then start the bot
const startBot = async () => {
    try {
        
        bot.launch();
        console.log('✅ System is now live...');
    } catch (error) {
        console.error('❌ Error starting bot:', error);
    }
};

// Clean up existing users with undefined adminId

startBot();

process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
