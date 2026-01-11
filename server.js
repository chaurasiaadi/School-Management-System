// ✅ STAR LIGHT SCHOOL BACKEND - COMPLETE WITH NOTICE BOARD & SUGGESTIONS APIs - FIXED
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";
import rateLimit from "express-rate-limit";
import multer from "multer";
import fs from "fs";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "public")));

const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use("/uploads", express.static(uploadsDir));

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Only images (JPEG, JPG, PNG) and PDFs are allowed!"));
    }
  },
});

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later.",
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many login attempts, please try again after 15 minutes.",
  skipSuccessfulRequests: true,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: "Too many registration attempts, please try again later.",
});

app.use("/api/", apiLimiter);

// Database Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch((err) => {
    console.error("❌ MongoDB Connection Error:", err);
    process.exit(1);
  });

// ========== SCHEMAS ==========

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 50 },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  role: { type: String, enum: ["student", "staff", "admin"], default: "student" },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

const studentRegistrationSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  fatherName: { type: String, required: true, trim: true },
  motherName: { type: String, required: true, trim: true },
  gender: { type: String, required: true, enum: ["male", "female", "other"] },
  dateOfBirth: { type: Date, required: true },
  class: { type: String, required: true },
  medium: { type: String, required: true, enum: ["english", "hindi"] },
  contactNumber: { type: String, required: true },
  email: { type: String, required: true, lowercase: true },
  aadharNumber: { type: String, required: true, unique: true },
  address: { type: String, required: true },
  disability: { type: String, enum: ["yes", "no"], default: "no" },
  photo: { type: String },
  marksheet: { type: String },
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});

const StudentRegistration = mongoose.model("StudentRegistration", studentRegistrationSchema);

const staffRegistrationSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  fatherName: { type: String, required: true, trim: true },
  maritalStatus: { type: String, required: true, enum: ["single", "married", "divorced", "widowed"] },
  contactNumber: { type: String, required: true },
  email: { type: String, required: true, lowercase: true },
  aadharNumber: { type: String, required: true, unique: true },
  highestQualification: { type: String, required: true },
  mainSubject: { type: String, required: true },
  hasBEd: { type: String, enum: ["yes", "no"], default: "no" },
  hasDEd: { type: String, enum: ["yes", "no"], default: "no" },
  dateOfBirth: { type: Date, required: true },
  twelfthPassingSubject: { type: String, required: true },
  photo: { type: String },
  twelfthMarksheet: { type: String },
  qualificationMarksheet: { type: String },
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});

const StaffRegistration = mongoose.model("StaffRegistration", staffRegistrationSchema);

const eventSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  date: { type: Date, required: true },
  type: { type: String, required: true, enum: ["holiday", "festival", "exam", "event", "other"] },
  description: { type: String, trim: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});

const Event = mongoose.model("Event", eventSchema);

const contactSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true, lowercase: true },
  phone: { type: String, trim: true },
  subject: { type: String, trim: true },
  message: { type: String, required: true },
  status: { type: String, enum: ["new", "read", "replied"], default: "new" },
  createdAt: { type: Date, default: Date.now },
});

const Contact = mongoose.model("Contact", contactSchema);

const noticeSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  content: { type: String, required: true, trim: true },
  priority: { type: String, enum: ["info", "important", "urgent"], default: "info" },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Notice = mongoose.model("Notice", noticeSchema);

const suggestionSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  role: { type: String, required: true, enum: ["parent", "student", "staff", "other"] },
  email: { type: String, required: true, trim: true, lowercase: true },
  category: { type: String, required: true, enum: ["academic", "facilities", "staff", "transport", "events", "other"] },
  suggestion: { type: String, required: true, trim: true },
  status: { type: String, enum: ["draft", "important", "ignored"], default: "draft" },
  adminComment: { type: String, trim: true },
  submittedAt: { type: Date, default: Date.now },
  reviewedAt: { type: Date },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});

const Suggestion = mongoose.model("Suggestion", suggestionSchema);

// ========== JWT MIDDLEWARE ==========

const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(403).json({ success: false, msg: "No token provided. Access denied." });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, msg: "Invalid or expired token." });
  }
};

const verifyAdmin = (req, res, next) => {
  if (req.userRole !== "admin") {
    return res.status(403).json({ success: false, msg: "Access denied. Admin only." });
  }
  next();
};

const verifyStudent = (req, res, next) => {
  if (req.userRole !== "student") {
    return res.status(403).json({ success: false, msg: "Access denied. Student only." });
  }
  next();
};

const verifyStaff = (req, res, next) => {
  if (req.userRole !== "staff") {
    return res.status(403).json({ success: false, msg: "Access denied. Staff only." });
  }
  next();
};

// ========== AUTHENTICATION ROUTES ==========

app.post("/api/register", registerLimiter, [
  body("username").trim().isLength({ min: 3, max: 50 }).matches(/^[a-zA-Z0-9_]+$/),
  body("email").isEmail().normalizeEmail(),
  body("password").isLength({ min: 6 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  const { username, email, password, role } = req.body;
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ success: false, msg: "Username or email already exists" });
    }
    const user = new User({ username, email, password, role: role || "student" });
    await user.save();
    res.status(201).json({ success: true, msg: "Registration successful!" });
  } catch (err) {
    console.error("Registration Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.post("/api/login", authLimiter, [
  body("username").trim().notEmpty(),
  body("password").notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  const { username, password, role } = req.body;
  try {
    const user = await User.findOne({
      $or: [{ username: username }, { email: username }],
    });
    if (!user) {
      return res.status(401).json({ success: false, msg: "Invalid credentials" });
    }
    if (!user.isActive) {
      return res.status(403).json({ success: false, msg: "Account deactivated. Contact admin." });
    }
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, msg: "Invalid credentials" });
    }
    if (role && user.role !== role) {
      return res.status(403).json({ success: false, msg: `Access denied. This is a ${role} login.` });
    }
    user.lastLogin = new Date();
    await user.save();
    const token = jwt.sign({ id: user._id, username: user.username, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({
      success: true,
      msg: "Login successful!",
      token,
      user: { id: user._id, username: user.username, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.post("/api/change-password", verifyToken, [
  body("currentPassword").notEmpty(),
  body("newPassword").isLength({ min: 6 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  const { currentPassword, newPassword } = req.body;
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }
    const isValid = await user.comparePassword(currentPassword);
    if (!isValid) {
      return res.status(401).json({ success: false, msg: "Current password incorrect" });
    }
    user.password = newPassword;
    await user.save();
    res.json({ success: true, msg: "Password changed successfully" });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== STUDENT REGISTRATION ROUTES ==========

app.post("/api/register-student", registerLimiter, upload.fields([
  { name: "photo", maxCount: 1 },
  { name: "marksheet", maxCount: 1 },
]), [
  body("fullName").trim().notEmpty(),
  body("fatherName").trim().notEmpty(),
  body("motherName").trim().notEmpty(),
  body("gender").isIn(["male", "female", "other"]),
  body("dateOfBirth").notEmpty(),
  body("class").trim().notEmpty(),
  body("medium").isIn(["english", "hindi"]),
  body("contactNumber").trim().isMobilePhone(),
  body("email").isEmail().normalizeEmail(),
  body("aadharNumber").trim().isLength({ min: 12, max: 12 }),
  body("address").trim().notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  try {
    const existingStudent = await StudentRegistration.findOne({ aadharNumber: req.body.aadharNumber });
    if (existingStudent) {
      return res.status(400).json({ success: false, msg: "Aadhar number already registered" });
    }
    
    const existingRegistration = await StudentRegistration.findOne({
      $or: [{ contactNumber: req.body.contactNumber }, { email: req.body.email }]
    });
    if (existingRegistration) {
      return res.status(400).json({
        success: false,
        msg: existingRegistration.contactNumber === req.body.contactNumber ? "Contact number already registered" : "Email already registered"
      });
    }
    
    const studentData = {
      ...req.body,
      photo: req.files?.photo ? req.files.photo[0].filename : null,
      marksheet: req.files?.marksheet ? req.files.marksheet[0].filename : null,
    };
    const student = new StudentRegistration(studentData);
    await student.save();
    
    console.log(`✅ Student registration submitted: ${req.body.fullName} - Awaiting admin approval`);
    res.status(201).json({
      success: true,
      msg: "Registration submitted successfully! You will receive login credentials after admin approval.",
      registrationId: student._id,
    });
  } catch (err) {
    console.error("Student Registration Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/student-registrations", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const students = await StudentRegistration.find().sort({ createdAt: -1 });
    res.json({ success: true, students });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/student-registrations/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const student = await StudentRegistration.findById(req.params.id);
    if (!student) {
      return res.status(404).json({ success: false, msg: "Student not found" });
    }
    res.json({ success: true, student });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.put("/api/student-registrations/:id/status", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ success: false, msg: "Invalid status" });
    }
    
    const student = await StudentRegistration.findById(req.params.id);
    if (!student) {
      return res.status(404).json({ success: false, msg: "Student not found" });
    }
    
    if (status === "approved" && !student.userId) {
      const existingUser = await User.findOne({
        $or: [{ username: student.contactNumber }, { email: student.email }]
      });
      
      if (existingUser) {
        return res.status(400).json({
          success: false,
          msg: "User account with this contact number or email already exists"
        });
      }
      
      const newUser = new User({
        username: student.contactNumber,
        email: student.email,
        password: student.dateOfBirth.toISOString().split('T')[0],
        role: "student",
      });
      await newUser.save();
      
      student.userId = newUser._id;
      console.log(`✅ User account created: ${student.fullName} | Login: ${student.contactNumber} / ${student.dateOfBirth.toISOString().split('T')[0]}`);
    }
    
    student.status = status;
    await student.save();
    
    if (student.userId) {
      await User.findByIdAndUpdate(student.userId, { isActive: status === "approved" });
    }
    
    res.json({ success: true, msg: `Student ${status}`, student });
  } catch (err) {
    console.error("Error updating student status:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== STAFF REGISTRATION ROUTES ==========

app.post("/api/register-staff", registerLimiter, upload.fields([
  { name: "photo", maxCount: 1 },
  { name: "twelfthMarksheet", maxCount: 1 },
  { name: "qualificationMarksheet", maxCount: 1 },
]), [
  body("fullName").trim().notEmpty(),
  body("fatherName").trim().notEmpty(),
  body("maritalStatus").isIn(["single", "married", "divorced", "widowed"]),
  body("contactNumber").trim().isMobilePhone(),
  body("email").isEmail().normalizeEmail(),
  body("aadharNumber").trim().isLength({ min: 12, max: 12 }),
  body("highestQualification").trim().notEmpty(),
  body("mainSubject").trim().notEmpty(),
  body("dateOfBirth").notEmpty(),
  body("twelfthPassingSubject").trim().notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  try {
    const existingStaff = await StaffRegistration.findOne({ aadharNumber: req.body.aadharNumber });
    if (existingStaff) {
      return res.status(400).json({ success: false, msg: "Aadhar number already registered" });
    }
    
    const existingRegistration = await StaffRegistration.findOne({
      $or: [{ contactNumber: req.body.contactNumber }, { email: req.body.email }]
    });
    if (existingRegistration) {
      return res.status(400).json({
        success: false,
        msg: existingRegistration.contactNumber === req.body.contactNumber ? "Contact number already registered" : "Email already registered"
      });
    }
    
    const staffData = {
      ...req.body,
      photo: req.files?.photo ? req.files.photo[0].filename : null,
      twelfthMarksheet: req.files?.twelfthMarksheet ? req.files.twelfthMarksheet[0].filename : null,
      qualificationMarksheet: req.files?.qualificationMarksheet ? req.files.qualificationMarksheet[0].filename : null,
    };
    const staff = new StaffRegistration(staffData);
    await staff.save();
    
    console.log(`✅ Staff registration submitted: ${req.body.fullName} - Awaiting admin approval`);
    res.status(201).json({
      success: true,
      msg: "Registration submitted successfully! You will receive login credentials after admin approval.",
      registrationId: staff._id,
    });
  } catch (err) {
    console.error("Staff Registration Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/staff-registrations", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const staff = await StaffRegistration.find().sort({ createdAt: -1 });
    res.json({ success: true, staff });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/staff-registrations/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const staff = await StaffRegistration.findById(req.params.id);
    if (!staff) {
      return res.status(404).json({ success: false, msg: "Staff not found" });
    }
    res.json({ success: true, staff });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.put("/api/staff-registrations/:id/status", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ success: false, msg: "Invalid status" });
    }
    
    const staff = await StaffRegistration.findById(req.params.id);
    if (!staff) {
      return res.status(404).json({ success: false, msg: "Staff not found" });
    }
    
    if (status === "approved" && !staff.userId) {
      const existingUser = await User.findOne({
        $or: [{ username: staff.contactNumber }, { email: staff.email }]
      });
      
      if (existingUser) {
        return res.status(400).json({
          success: false,
          msg: "User account with this contact number or email already exists"
        });
      }
      
      const newUser = new User({
        username: staff.contactNumber,
        email: staff.email,
        password: staff.dateOfBirth.toISOString().split('T')[0],
        role: "staff",
      });
      await newUser.save();
      
      staff.userId = newUser._id;
      console.log(`✅ User account created: ${staff.fullName} | Login: ${staff.contactNumber} / ${staff.dateOfBirth.toISOString().split('T')[0]}`);
    }
    
    staff.status = status;
    await staff.save();
    
    if (staff.userId) {
      await User.findByIdAndUpdate(staff.userId, { isActive: status === "approved" });
    }
    
    res.json({ success: true, msg: `Staff ${status}`, staff });
  } catch (err) {
    console.error("Error updating staff status:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== STUDENT DASHBOARD APIs ==========

app.get("/api/student/my-registration", verifyToken, verifyStudent, async (req, res) => {
  try {
    const studentReg = await StudentRegistration.findOne({ userId: req.userId });
    
    if (!studentReg) {
      return res.status(404).json({ 
        success: false, 
        msg: "Registration details not found" 
      });
    }
    
    res.json({ 
      success: true, 
      registration: studentReg 
    });
  } catch (err) {
    console.error("Error fetching student registration:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/student/my-profile", verifyToken, verifyStudent, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    const studentReg = await StudentRegistration.findOne({ userId: req.userId });
    
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }
    
    res.json({ 
      success: true, 
      user,
      registration: studentReg 
    });
  } catch (err) {
    console.error("Error fetching student profile:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/student/dashboard-stats", verifyToken, verifyStudent, async (req, res) => {
  try {
    const studentReg = await StudentRegistration.findOne({ userId: req.userId });
    
    const upcomingEvents = await Event.countDocuments({ 
      date: { $gte: new Date() } 
    });
    
    const stats = {
      class: studentReg?.class || "Not Available",
      status: studentReg?.status || "pending",
      medium: studentReg?.medium || "Not Available",
      upcomingEvents: upcomingEvents,
      registrationDate: studentReg?.createdAt || null,
      isApproved: studentReg?.status === "approved"
    };
    
    res.json({ success: true, stats });
  } catch (err) {
    console.error("Error fetching student stats:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== STAFF DASHBOARD APIs ==========

app.get("/api/staff/my-registration", verifyToken, verifyStaff, async (req, res) => {
  try {
    const staffReg = await StaffRegistration.findOne({ userId: req.userId });
    
    if (!staffReg) {
      return res.status(404).json({ 
        success: false, 
        msg: "Registration details not found" 
      });
    }
    
    res.json({ 
      success: true, 
      registration: staffReg 
    });
  } catch (err) {
    console.error("Error fetching staff registration:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/staff/my-profile", verifyToken, verifyStaff, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    const staffReg = await StaffRegistration.findOne({ userId: req.userId });
    
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }
    
    res.json({ 
      success: true, 
      user,
      registration: staffReg 
    });
  } catch (err) {
    console.error("Error fetching staff profile:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== NOTICE BOARD APIs ==========

app.get("/api/notices", async (req, res) => {
  try {
    const notices = await Notice.find()
      .sort({ createdAt: -1 })
      .select('title content priority createdAt updatedAt');
    
    res.json({ 
      success: true, 
      notices,
      count: notices.length 
    });
  } catch (err) {
    console.error("Error fetching notices:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/notices/:id", async (req, res) => {
  try {
    const notice = await Notice.findById(req.params.id);
    
    if (!notice) {
      return res.status(404).json({ success: false, msg: "Notice not found" });
    }
    
    res.json({ success: true, notice });
  } catch (err) {
    console.error("Error fetching notice:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.post("/api/notices", verifyToken, verifyAdmin, [
  body("title").trim().notEmpty().isLength({ min: 3, max: 200 }),
  body("content").trim().notEmpty().isLength({ min: 10, max: 2000 }),
  body("priority").optional().isIn(["info", "important", "urgent"]),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  
  try {
    const { title, content, priority } = req.body;
    
    const notice = new Notice({
      title,
      content,
      priority: priority || "info",
      createdBy: req.userId
    });
    
    await notice.save();
    
    console.log(`✅ Notice created: "${title}" by admin ${req.userId}`);
    
    res.status(201).json({ 
      success: true, 
      msg: "Notice created successfully!",
      notice 
    });
  } catch (err) {
    console.error("Error creating notice:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.put("/api/notices/:id", verifyToken, verifyAdmin, [
  body("title").optional().trim().isLength({ min: 3, max: 200 }),
  body("content").optional().trim().isLength({ min: 10, max: 2000 }),
  body("priority").optional().isIn(["info", "important", "urgent"]),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  
  try {
    const { title, content, priority } = req.body;
    
    const notice = await Notice.findById(req.params.id);
    
    if (!notice) {
      return res.status(404).json({ success: false, msg: "Notice not found" });
    }
    
    if (title) notice.title = title;
    if (content) notice.content = content;
    if (priority) notice.priority = priority;
    notice.updatedAt = new Date();
    
    await notice.save();
    
    console.log(`✅ Notice updated: "${notice.title}" by admin ${req.userId}`);
    
    res.json({ 
      success: true, 
      msg: "Notice updated successfully!",
      notice 
    });
  } catch (err) {
    console.error("Error updating notice:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.delete("/api/notices/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const notice = await Notice.findByIdAndDelete(req.params.id);
    
    if (!notice) {
      return res.status(404).json({ success: false, msg: "Notice not found" });
    }
    
    console.log(`✅ Notice deleted: "${notice.title}" by admin ${req.userId}`);
    
    res.json({ 
      success: true, 
      msg: "Notice deleted successfully!" 
    });
  } catch (err) {
    console.error("Error deleting notice:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/notices/stats/priority", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const stats = {
      info: await Notice.countDocuments({ priority: "info" }),
      important: await Notice.countDocuments({ priority: "important" }),
      urgent: await Notice.countDocuments({ priority: "urgent" }),
      total: await Notice.countDocuments()
    };
    
    res.json({ success: true, stats });
  } catch (err) {
    console.error("Error fetching notice stats:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== SUGGESTIONS APIs (✅ FIXED) ==========

app.post("/api/suggestions", [
  body("name").trim().notEmpty().isLength({ min: 2, max: 100 }),
  body("role").isIn(["parent", "student", "staff", "other"]),
  body("email").isEmail().normalizeEmail(),
  body("category").isIn(["academic", "facilities", "staff", "transport", "events", "other"]),
  body("suggestion").trim().notEmpty().isLength({ min: 10, max: 1000 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  
  try {
    const { name, role, email, category, suggestion, submittedAt } = req.body;
    
    const newSuggestion = new Suggestion({
      name,
      role,
      email,
      category,
      suggestion,
      submittedAt: submittedAt || new Date()
    });
    
    await newSuggestion.save();
    
    console.log(`✅ New suggestion received from: ${name} (${role}) - Category: ${category}`);
    
    res.status(201).json({ 
      success: true, 
      msg: "Suggestion submitted successfully! Thank you for your valuable feedback.",
      suggestionId: newSuggestion._id
    });
  } catch (err) {
    console.error("Error submitting suggestion:", err);
    res.status(500).json({ success: false, msg: "Server error. Please try again later." });
  }
});

app.get("/api/suggestions", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status, category, role } = req.query;
    
    let query = {};
    if (status) query.status = status;
    if (category) query.category = category;
    if (role) query.role = role;
    
    const suggestions = await Suggestion.find(query)
      .sort({ submittedAt: -1 })
      .populate('reviewedBy', 'username email');
    
    res.json({ 
      success: true, 
      suggestions,
      count: suggestions.length 
    });
  } catch (err) {
    console.error("Error fetching suggestions:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/suggestions/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const suggestion = await Suggestion.findById(req.params.id)
      .populate('reviewedBy', 'username email');
    
    if (!suggestion) {
      return res.status(404).json({ success: false, msg: "Suggestion not found" });
    }
    
    res.json({ success: true, suggestion });
  } catch (err) {
    console.error("Error fetching suggestion:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ✅ FIXED: Status validation now matches schema enum
app.put("/api/suggestions/:id/status", verifyToken, verifyAdmin, [
  body("status").isIn(["draft", "important", "ignored"]),
  body("adminComment").optional().trim().isLength({ max: 500 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  
  try {
    const { status, adminComment } = req.body;
    
    const suggestion = await Suggestion.findById(req.params.id);
    
    if (!suggestion) {
      return res.status(404).json({ success: false, msg: "Suggestion not found" });
    }
    
    suggestion.status = status;
    if (adminComment) suggestion.adminComment = adminComment;
    suggestion.reviewedAt = new Date();
    suggestion.reviewedBy = req.userId;
    
    await suggestion.save();
    
    console.log(`✅ Suggestion status updated to "${status}" by admin ${req.userId}`);
    
    res.json({ 
      success: true, 
      msg: "Suggestion status updated successfully!",
      suggestion 
    });
  } catch (err) {
    console.error("Error updating suggestion status:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.delete("/api/suggestions/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const suggestion = await Suggestion.findByIdAndDelete(req.params.id);
    
    if (!suggestion) {
      return res.status(404).json({ success: false, msg: "Suggestion not found" });
    }
    
    console.log(`✅ Suggestion deleted by admin ${req.userId}`);
    
    res.json({ 
      success: true, 
      msg: "Suggestion deleted successfully!" 
    });
  } catch (err) {
    console.error("Error deleting suggestion:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ✅ FIXED: Stats now use correct status values
app.get("/api/suggestions/stats/summary", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const stats = {
      total: await Suggestion.countDocuments(),
      draft: await Suggestion.countDocuments({ status: "draft" }),
      important: await Suggestion.countDocuments({ status: "important" }),
      ignored: await Suggestion.countDocuments({ status: "ignored" }),
      byCategory: {
        academic: await Suggestion.countDocuments({ category: "academic" }),
        facilities: await Suggestion.countDocuments({ category: "facilities" }),
        staff: await Suggestion.countDocuments({ category: "staff" }),
        transport: await Suggestion.countDocuments({ category: "transport" }),
        events: await Suggestion.countDocuments({ category: "events" }),
        other: await Suggestion.countDocuments({ category: "other" })
      },
      byRole: {
        parent: await Suggestion.countDocuments({ role: "parent" }),
        student: await Suggestion.countDocuments({ role: "student" }),
        staff: await Suggestion.countDocuments({ role: "staff" }),
        other: await Suggestion.countDocuments({ role: "other" })
      }
    };
    
    res.json({ success: true, stats });
  } catch (err) {
    console.error("Error fetching suggestion stats:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== EVENTS ROUTES ==========

app.get("/api/events", async (req, res) => {
  try {
    const events = await Event.find().sort({ date: 1 });
    res.json({ success: true, events });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.post("/api/events", verifyToken, verifyAdmin, [
  body("title").trim().notEmpty(),
  body("date").isISO8601(),
  body("type").isIn(["holiday", "festival", "exam", "event", "other"]),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  try {
    const event = new Event({ ...req.body, createdBy: req.userId });
    await event.save();
    res.status(201).json({ success: true, event });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.put("/api/events/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const event = await Event.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json({ success: true, event });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.delete("/api/events/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    await Event.findByIdAndDelete(req.params.id);
    res.json({ success: true, msg: "Event deleted" });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== CONTACT ROUTES ==========

app.post("/api/contact", [
  body("name").trim().notEmpty(),
  body("email").isEmail().normalizeEmail(),
  body("message").trim().isLength({ min: 10 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  try {
    const contact = new Contact(req.body);
    await contact.save();
    res.json({ success: true, msg: "Message sent successfully!" });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/contacts", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.json({ success: true, contacts });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.put("/api/contacts/:id/status", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const contact = await Contact.findByIdAndUpdate(req.params.id, { status }, { new: true });
    res.json({ success: true, contact });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// Delete contact message (Admin only)
app.delete("/api/contacts/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const contact = await Contact.findByIdAndDelete(req.params.id);
    
    if (!contact) {
      return res.status(404).json({ success: false, msg: "Contact message not found" });
    }
    
    console.log(`✅ Contact message deleted by admin ${req.userId}`);
    
    res.json({ 
      success: true, 
      msg: "Message deleted successfully!" 
    });
  } catch (err) {
    console.error("Error deleting contact:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== STATS ROUTE ==========

app.get("/api/stats", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const stats = {
      totalStudents: await StudentRegistration.countDocuments(),
      totalStaff: await StaffRegistration.countDocuments(),
      totalUsers: await User.countDocuments(),
      pendingStudents: await StudentRegistration.countDocuments({ status: "pending" }),
      pendingStaff: await StaffRegistration.countDocuments({ status: "pending" }),
      approvedStudents: await StudentRegistration.countDocuments({ status: "approved" }),
      approvedStaff: await StaffRegistration.countDocuments({ status: "approved" }),
      rejectedStudents: await StudentRegistration.countDocuments({ status: "rejected" }),
      rejectedStaff: await StaffRegistration.countDocuments({ status: "rejected" }),
      totalEvents: await Event.countDocuments(),
      totalNotices: await Notice.countDocuments(),
      urgentNotices: await Notice.countDocuments({ priority: "urgent" }),
      importantNotices: await Notice.countDocuments({ priority: "important" }),
      unreadMessages: await Contact.countDocuments({ status: "new" }),
      totalMessages: await Contact.countDocuments(),
      totalSuggestions: await Suggestion.countDocuments(),
      draftSuggestions: await Suggestion.countDocuments({ status: "draft" }),
      importantSuggestions: await Suggestion.countDocuments({ status: "important" }),
    };
    res.json({ success: true, stats });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== USER MANAGEMENT ROUTES ==========

app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.get("/api/users/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.put("/api/users/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true }).select("-password");
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.delete("/api/users/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (req.params.id === req.userId) {
      return res.status(400).json({ success: false, msg: "Cannot delete your own account" });
    }
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true, msg: "User deleted" });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

app.patch("/api/users/:id/toggle-active", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (req.params.id === req.userId) {
      return res.status(400).json({ success: false, msg: "Cannot deactivate your own account" });
    }
    user.isActive = !user.isActive;
    await user.save();
    res.json({ success: true, msg: `User ${user.isActive ? 'activated' : 'deactivated'}` });
  } catch (err) {
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ========== UTILITY ROUTES ==========

app.get("/api/health", (req, res) => {
  res.json({ success: true, msg: "Server is running" });
});

app.get("/api/db-test", async (req, res) => {
  const states = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
  res.json({ success: true, database: states[mongoose.connection.readyState] });
});

// ========== FRONTEND ROUTES ==========

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("*", (req, res, next) => {
  if (req.url.startsWith("/api/") || req.url.startsWith("/uploads/")) {
    return next();
  }
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// ========== ERROR HANDLERS ==========

app.use((req, res) => {
  res.status(404).json({ success: false, msg: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("Error:", err);
  res.status(err.status || 500).json({
    success: false,
    msg: err.message || "Internal server error",
  });
});

// ========== SERVER START ==========

const server = app.listen(PORT, () => {
  console.log(`\n${"=".repeat(70)}`);
  console.log(`⭐ STAR LIGHT SCHOOL BACKEND - FIXED VERSION`);
  console.log(`${"=".repeat(70)}`);
  console.log(`✅ Server: http://localhost:${PORT}`);
  console.log(`✅ Database: Connected`);
  console.log(`✅ Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`${"=".repeat(70)}`);
  console.log(`🔒 Security: Enabled`);
  console.log(`   • Password Hashing (bcrypt)`);
  console.log(`   • JWT Authentication`);
  console.log(`   • Input Validation`);
  console.log(`   • Rate Limiting`);
  console.log(`${"=".repeat(70)}`);
  console.log(`✅ FIXED: Suggestion Status Update`);
  console.log(`   • Status values: draft, important, ignored`);
  console.log(`   • Admin can now update suggestion status`);
  console.log(`   • Stats endpoint fixed`);
  console.log(`${"=".repeat(70)}`);
  console.log(`💡 Suggestions APIs:`);
  console.log(`   • POST   /api/suggestions (Public - Submit)`);
  console.log(`   • GET    /api/suggestions (Admin - View all)`);
  console.log(`   • GET    /api/suggestions/:id (Admin - View one)`);
  console.log(`   • PUT    /api/suggestions/:id/status (Admin - Update) ✅ FIXED`);
  console.log(`   • DELETE /api/suggestions/:id (Admin - Delete)`);
  console.log(`   • GET    /api/suggestions/stats/summary (Admin - Stats) ✅ FIXED`);
  console.log(`${"=".repeat(70)}\n`);
});

// ========== GRACEFUL SHUTDOWN ==========

process.on("SIGTERM", () => {
  console.log("\n👋 SIGTERM - Closing server...");
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log("💤 Server closed");
      process.exit(0);
    });
  });
});

process.on("SIGINT", () => {
  console.log("\n👋 SIGINT - Closing server...");
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log("💤 Server closed");
      process.exit(0);
    });
  });
});

process.on("unhandledRejection", (err) => {
  console.error("🚨 UNHANDLED REJECTION:", err);
  server.close(() => process.exit(1));
});

process.on("uncaughtException", (err) => {
  console.error("🚨 UNCAUGHT EXCEPTION:", err);
  process.exit(1);
});