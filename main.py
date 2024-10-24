import streamlit as st
import pandas as pd
from datetime import datetime
import json
from pathlib import Path
import hashlib
import re

def load_data(filename):
    """Load existing data from JSON file."""
    data_file = Path(filename)
    if data_file.exists():
        with open(data_file, "r") as f:
            return pd.DataFrame(json.load(f))
    return pd.DataFrame()

def save_data(df, filename):
    """Save data to JSON file."""
    with open(filename, "w") as f:
        json.dump(df.to_dict('records'), f, indent=4)

def hash_password(password):
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_email(email):
    """Validate email format."""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def initialize_session_state():
    """Initialize session state variables."""
    # Authentication states
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None
        
    # Load data
    if 'users' not in st.session_state:
        st.session_state.users = load_data("users.json")
    if 'parking_data' not in st.session_state:
        st.session_state.parking_data = load_data("parking_data.json")

def authenticate_user(email, password):
    """Authenticate user and set session state."""
    users_df = st.session_state.users
    hashed_password = hash_password(password)
    
    if not users_df.empty and any((users_df['email'] == email) & (users_df['password'] == hashed_password)):
        st.session_state.authenticated = True
        st.session_state.current_user = email
        return True
    return False

def login_register_page():
    """Handle login and registration."""
    st.title("🚗 Teacher Parking Management System")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.header("Login")
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")
            
            if submit:
                if email and password:
                    if authenticate_user(email, password):
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid email or password")
                else:
                    st.error("Please fill in all fields")
    
    with tab2:
        st.header("Register")
        with st.form("register_form"):
            new_email = st.text_input("Email")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Register")
            
            if submit:
                if new_email and new_password and confirm_password:
                    if not is_valid_email(new_email):
                        st.error("Please enter a valid email address")
                        return
                    
                    if new_password != confirm_password:
                        st.error("Passwords do not match")
                        return
                    
                    users_df = st.session_state.users
                    if not users_df.empty and any(users_df['email'] == new_email):
                        st.error("Email already registered")
                        return
                    
                    # Create new user
                    new_user = {
                        'email': new_email,
                        'password': hash_password(new_password),
                        'registration_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    # Add to dataframe
                    st.session_state.users = pd.concat([
                        users_df,
                        pd.DataFrame([new_user])
                    ], ignore_index=True)
                    
                    # Save users data
                    save_data(st.session_state.users, "users.json")
                    st.success("Registration successful! Please login.")
                else:
                    st.error("Please fill in all fields")

def logout():
    """Handle user logout."""
    st.session_state.authenticated = False
    st.session_state.current_user = None
    st.rerun()

def main_application():
    """Main application interface."""
    st.title("🚗 Teacher Parking Management System")
    
    # Add logout button
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("Logout"):
            logout()
    with col1:
        st.write(f"Welcome, {st.session_state.current_user}")
    
    # Create tabs for different functionalities
    tab1, tab2 = st.tabs(["Register Parking", "View/Manage Registrations"])
    
    with tab1:
        st.header("Register New Parking")
        
        with st.form("parking_registration"):
            teacher_name = st.text_input("Teacher Name")
            car_model = st.text_input("Car Model")
            license_plate = st.text_input("License Plate Number")
            
            st.write("Select Parking Days:")
            col1, col2, col3 = st.columns(3)
            with col1:
                monday = st.checkbox("Monday")
                tuesday = st.checkbox("Tuesday")
            with col2:
                wednesday = st.checkbox("Wednesday")
                thursday = st.checkbox("Thursday")
            with col3:
                friday = st.checkbox("Friday")
            
            days = []
            for day, selected in [
                ("Monday", monday), ("Tuesday", tuesday),
                ("Wednesday", wednesday), ("Thursday", thursday),
                ("Friday", friday)
            ]:
                if selected:
                    days.append(day)
            
            submit_button = st.form_submit_button("Register Parking")
            
            if submit_button:
                if not teacher_name or not car_model or not license_plate or not days:
                    st.error("Please fill in all required fields and select at least one day.")
                else:
                    new_registration = {
                        "Teacher Name": teacher_name,
                        "Car Model": car_model,
                        "License Plate": license_plate,
                        "Parking Days": ", ".join(days),
                        "Registration Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "Registered By": st.session_state.current_user
                    }
                    
                    st.session_state.parking_data = pd.concat([
                        st.session_state.parking_data,
                        pd.DataFrame([new_registration])
                    ], ignore_index=True)
                    
                    save_data(st.session_state.parking_data, "parking_data.json")
                    st.success("Parking registration successful!")
    
    with tab2:
        st.header("Current Registrations")
        
        search_term = st.text_input("Search by teacher name or license plate:")
        
        df = st.session_state.parking_data
        if search_term:
            df = df[
                df["Teacher Name"].str.contains(search_term, case=False) |
                df["License Plate"].str.contains(search_term, case=False)
            ]
        
        if not df.empty:
            for idx, row in df.iterrows():
                with st.expander(f"{row['Teacher Name']} - {row['Car Model']}"):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**License Plate:** {row['License Plate']}")
                        st.write(f"**Parking Days:** {row['Parking Days']}")
                        st.write(f"**Registration Date:** {row['Registration Date']}")
                        st.write(f"**Registered By:** {row.get('Registered By', 'Unknown')}")
                    with col2:
                        if st.button("Delete Registration", key=f"delete_{idx}"):
                            st.session_state.parking_data = st.session_state.parking_data.drop(idx)
                            save_data(st.session_state.parking_data, "parking_data.json")
                            st.rerun()
        else:
            st.info("No registrations found.")

def main():
    st.set_page_config(page_title="Teacher Parking Management", layout="wide")
    
    # Initialize session state
    initialize_session_state()
    
    # Show appropriate page based on authentication status
    if not st.session_state.authenticated:
        login_register_page()
    else:
        main_application()

if __name__ == "__main__":
    main()