package com.example.SpringSecurity.student;

public class Student {

    private final Integer StudentId;
    private final String studentName;

    public Student(Integer studentId, String studentName) {
        StudentId = studentId;
        this.studentName = studentName;
    }

    public Integer getStudentId() {
        return StudentId;
    }

    public String getStudentName() {
        return studentName;
    }

    @Override
    public String toString() {
        return "Student{" +
                "StudentId=" + StudentId +
                ", studentName='" + studentName + '\'' +
                '}';
    }
}
