import express from "express";
import { isAdmin, isAuth } from "../middlewares/isAuth.js";
import {  createCourse,addLectures,deleteLecture ,deleteCourse,getAllStats,updateRole,getAllUser} from "../controllers/admin.js";
import { uploadFiles } from "../middlewares/multer.js";


const router = express.Router();


router.post('/course/new',isAuth,isAdmin,uploadFiles,
  createCourse)
router.post('/course/:id',isAuth,isAdmin,uploadFiles,
  addLectures)
  router.delete("/lecture/:id" , isAuth,isAdmin,deleteLecture)
  router.delete("/course/:id" , isAuth,isAdmin,deleteCourse)
  router.get("/stats",isAuth,isAdmin,getAllStats)
  router.put("/user/:id", isAuth, isAdmin, updateRole);
router.get("/users", isAuth, isAdmin, getAllUser);
export default router;