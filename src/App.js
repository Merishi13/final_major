import React, { useState } from "react";
import { BrowserRouter, Routes, Route, Link, Navigate } from "react-router-dom";
import Navbar from "./components/Navbar";
import Footer from "./components/Footer";
import HospitalHome from "./components/HospitalHome";
import Login from "./components/UserLogin";
import HospitalLogin from "./components/Hospitallogin";
import Usersignup from "./components/Usersignup";
import AccessDetails from "./components/Accessdetails";
import AccessPRecords from "./components/AccessPrecords";
import UpdateFiles from "./components/UploadFiles";
import PatientHome from "./components/PatientHome";
import Fillform from "./components/Fillform";
import AccessRecords from "./components/AccessRecords";

function App() {
  const [showNavbar, setShowNavbar] = useState(false);
  const [patientBar, setPatientbar] = useState(false);
  const [hospitalBar, setHosbar] = useState(false);

  return (
    <>  
      {showNavbar && (patientBar || hospitalBar) && (
        <Navbar
          abouttext="About Us"
          action1={hospitalBar ? "Hospital Home" : "Patient Home"}
          action2={
            hospitalBar ? "Access General Details" : "Fill Up General Details"
          }
          action3={hospitalBar ? "Access Patient Record" : "Access Record"}
          action4={hospitalBar ? "Upload Patient's Records" : ""}
        />
      )}
      <Routes>
        <Route
          path="/"
          element={
            <Login
              setShowNavbar={setShowNavbar}
              setHosbar={setHosbar}
              setPatientbar={setPatientbar}
            />
          }
        />
        <Route
          path="/Signup"
          element={
            <Usersignup
              setShowNavbar={setShowNavbar}
              setHosbar={setHosbar}
              setPatientbar={setPatientbar}
            />
          }
        />
        <Route
          path="/HospitalLogin"
          element={
            <HospitalLogin
              setShowNavbar={setShowNavbar}
              setHosbar={setHosbar}
              setPatientbar={setPatientbar}
            />
          }
        />
        <Route
          path="/HospitalHome"
          element={
            hospitalBar ? (
              <HospitalHome
                setShowNavbar={setShowNavbar}
                setHosbar={setHosbar}
                setPatientbar={setPatientbar}
              />
            ) : (
              <Navigate to="/PatientHome" replace />
            )
          }
        />
        <Route
          path="/PatientHome"
          element={
            !hospitalBar ? (
              <PatientHome
                setShowNavbar={setShowNavbar}
                setHosbar={setHosbar}
                setPatientbar={setPatientbar}
              />
            ) : (
              <Navigate to="/HospitalHome" replace />
            )
          }
        />
        <Route
          path="/AccessForm"
          element={
            hospitalBar ? (
              <AccessDetails
                setShowNavbar={setShowNavbar}
                setHosbar={setHosbar}
                setPatientbar={setPatientbar}
              />
            ) : (
              <Navigate to="/Fillform" replace />
            )
          }
        />
        <Route
          path="/Fillform"
          element={
            !hospitalBar ? (
              <Fillform
                setShowNavbar={setShowNavbar}
                setHosbar={setHosbar}
                setPatientbar={setPatientbar}
              />
            ) : (
              <Navigate to="/AccessForm" replace />
            )
          }
        />
        <Route
          path="/AccRecords"
          element={
            hospitalBar ? (
              <AccessPRecords
                setShowNavbar={setShowNavbar}
                setHosbar={setHosbar}
                setPatientbar={setPatientbar}
              />
            ) : (
              <Navigate to="/Accessrecords" />
            )
          }
        />
        <Route
          path="/Accessrecords"
          element={
            !hospitalBar ? (
              <AccessRecords
                setShowNavbar={setShowNavbar}
                setHosbar={setHosbar}
                setPatientbar={setPatientbar}
              />
            ) : (
              <Navigate to="/AccRecords" replace />
            )
          }
        />
        <Route
          path="/UpdateFiles"
          element={
            <UpdateFiles
              setShowNavbar={setShowNavbar}
              setHosbar={setHosbar}
              setPatientbar={setPatientbar}
            />
          }
        />
        {/* <Route
          path="/PatientHome"
          element={
            <PatientHome
              setShowNavbar={setShowNavbar}
              setHosbar={setHosbar}
              setPatientbar={setPatientbar}
            />
          }
        /> */}
        {/* <Route
          path="/Fillform"
          element={
            <Fillform
              setShowNavbar={setShowNavbar}
              setHosbar={setHosbar}
              setPatientbar={setPatientbar}
            />
          }
        /> */}
        {/* <Route
          path="/patientaccess"
          element={
            <AccessRecords
              setShowNavbar={setShowNavbar}
              setHosbar={setHosbar}
              setPatientbar={setPatientbar}
            />
          }
        /> */}
      </Routes>
      {showNavbar && <Footer footer="Jeevan Records" />}
    </>
  );
}

export default App;
