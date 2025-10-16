import dash
from dash import dcc, html, dash_table, no_update, ctx, MATCH, ALL
from dash.dependencies import Input, Output, State
import sqlite3  # For database interaction
import secrets  # For generating secure random tokens (e.g., patient IDs)
import pandas as pd  # For data manipulation and display in tables
import json  # For storing complex data (like form fields) in the database
from datetime import datetime  # For handling dates and timestamps
import dash_bootstrap_components as dbc  # For better styling and layout components
from urllib.parse import urlparse, parse_qs  # For parsing URL parameters
import bcrypt  # For hashing passwords securely
import os  # For interacting with the file system (e.g., creating directories)
import uuid  # For generating unique filenames for uploads
import base64 # For decoding file upload content
import flask # Used to create a route for downloading files

# --- File Storage Setup ---
# Define a directory to store uploaded files (like PDFs).
UPLOAD_DIRECTORY = "uploads"
# Create the directory if it doesn't already exist to prevent errors.
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)

# --- 1. DATABASE FUNCTIONS ---
# This section contains all functions that interact with the SQLite database.

def init_db():
    """
    Initializes the database and creates all necessary tables if they don't exist.
    Also creates a default 'admin' user on the first run.
    """
    with sqlite3.connect('medical_records.db') as conn:
        cursor = conn.cursor()
        # Create a table for classes/courses.
        cursor.execute("CREATE TABLE IF NOT EXISTS classes (id INTEGER PRIMARY KEY, class_name TEXT UNIQUE NOT NULL)")
        # Create a table for users with roles (student or admin).
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student', 'admin')))")
        # Create a linking table to manage which students are enrolled in which classes (many-to-many relationship).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_class_enrollment (
                user_id INTEGER NOT NULL, class_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, class_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE
            )""")
        # Create a linking table to manage which patient records are shared with which classes.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patient_class_permissions (
                patient_id TEXT NOT NULL, class_id INTEGER NOT NULL,
                PRIMARY KEY (patient_id, class_id),
                FOREIGN KEY (patient_id) REFERENCES patients (patient_id) ON DELETE CASCADE,
                FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE
            )""")
        # Create the main table for patient demographic information.
        cursor.execute("CREATE TABLE IF NOT EXISTS patients (id INTEGER PRIMARY KEY, patient_id TEXT UNIQUE NOT NULL, patient_name TEXT, dob_or_age TEXT, contact_info TEXT, insurance_details TEXT, created_by_user TEXT NOT NULL, FOREIGN KEY (created_by_user) REFERENCES users (username))")
        # Create a table to store individual documents/notes for each patient.
        cursor.execute("CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, patient_id TEXT NOT NULL, document_type TEXT NOT NULL, document_date TEXT, data TEXT, created_by_user TEXT NOT NULL, FOREIGN KEY (patient_id) REFERENCES patients (patient_id), FOREIGN KEY (created_by_user) REFERENCES users (username))")
        # Create a table for comments on documents.
        cursor.execute("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL, username TEXT NOT NULL, comment_text TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (document_id) REFERENCES documents (id), FOREIGN KEY (username) REFERENCES users (username))")

        # Check if the default 'admin' user exists. If not, create one.
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cursor.fetchone()[0] == 0:
            # Hash the default password before storing it. NEVER store plain text passwords.
            hashed = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', hashed, 'admin'))
        
        # Simple database migration: handle dropping an old column if it exists.
        try:
            cursor.execute("PRAGMA table_info(users)")
            if 'class_id' in [col[1] for col in cursor.fetchall()]:
                cursor.execute("ALTER TABLE users DROP COLUMN class_id")
        except sqlite3.OperationalError: pass
        
        conn.commit()

# --- Database Helper Functions ---
# Each function below performs a specific CRUD (Create, Read, Update, Delete) operation.

def create_class(class_name):
    """Adds a new class to the 'classes' table."""
    with sqlite3.connect('medical_records.db') as conn:
        conn.cursor().execute("INSERT INTO classes (class_name) VALUES (?)", (class_name,)); conn.commit()

def get_classes():
    """Retrieves a list of all classes from the database."""
    with sqlite3.connect('medical_records.db') as conn:
        conn.row_factory = sqlite3.Row  # Allows accessing columns by name.
        return [dict(row) for row in conn.cursor().execute("SELECT id, class_name FROM classes ORDER BY class_name").fetchall()]

def get_classes_with_students():
    """Retrieves classes and lists the students enrolled in each."""
    with sqlite3.connect('medical_records.db') as conn:
        query = "SELECT c.class_name, u.username FROM classes c LEFT JOIN user_class_enrollment uce ON c.id = uce.class_id LEFT JOIN users u ON uce.user_id = u.id WHERE u.role = 'student' ORDER BY c.class_name, u.username"
        df = pd.read_sql_query(query, conn)
        # Handle cases where there are classes but no students enrolled.
        if df.empty:
            all_classes_df = pd.read_sql_query("SELECT class_name FROM classes", conn)
            if all_classes_df.empty: return {}
            all_classes_df['username'] = None
            return all_classes_df.groupby('class_name')['username'].apply(list).to_dict()
        return df.groupby('class_name')['username'].apply(list).to_dict()

def get_shared_classes_for_patient(patient_id):
    """Gets the list of class IDs that a specific patient record is shared with."""
    with sqlite3.connect('medical_records.db') as conn:
        return [row[0] for row in conn.cursor().execute("SELECT class_id FROM patient_class_permissions WHERE patient_id = ?", (patient_id,)).fetchall()]

def update_patient_sharing(patient_id, class_ids):
    """Updates the sharing settings for a patient. Deletes old settings and inserts new ones."""
    with sqlite3.connect('medical_records.db') as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM patient_class_permissions WHERE patient_id = ?", (patient_id,))
        if class_ids: cursor.executemany("INSERT INTO patient_class_permissions (patient_id, class_id) VALUES (?, ?)", [(patient_id, cid) for cid in class_ids])
        conn.commit()

def get_all_users():
    """Retrieves all users and the classes they are enrolled in."""
    with sqlite3.connect('medical_records.db') as conn:
        conn.row_factory = sqlite3.Row
        query = "SELECT u.id, u.username, u.role, GROUP_CONCAT(uce.class_id) as class_ids FROM users u LEFT JOIN user_class_enrollment uce ON u.id = uce.user_id GROUP BY u.id, u.username, u.role ORDER BY u.role, u.username"
        users = [dict(row) for row in conn.cursor().execute(query).fetchall()]
        for user in users: user['class_ids'] = [int(cid) for cid in user['class_ids'].split(',')] if user['class_ids'] else []
        return users

def update_user_classes(username, class_ids):
    """Updates the class enrollments for a specific student."""
    with sqlite3.connect('medical_records.db') as conn:
        cursor = conn.cursor()
        user_id = cursor.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
        cursor.execute("DELETE FROM user_class_enrollment WHERE user_id = ?", (user_id,))
        if class_ids: cursor.executemany("INSERT INTO user_class_enrollment (user_id, class_id) VALUES (?, ?)", [(user_id, cid) for cid in class_ids])
        conn.commit()

def create_user(username, password, role, class_ids=None):
    """Creates a new user, hashes their password, and sets their class enrollments."""
    with sqlite3.connect('medical_records.db') as conn:
        cursor = conn.cursor()
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed, role))
        user_id = cursor.lastrowid
        if role == 'student' and class_ids:
            cursor.executemany("INSERT INTO user_class_enrollment (user_id, class_id) VALUES (?, ?)", [(user_id, cid) for cid in class_ids])
        conn.commit()

def verify_user(username, password):
    """Verifies a user's login credentials against the hashed password in the database."""
    with sqlite3.connect('medical_records.db') as conn:
        result = conn.cursor().execute("SELECT password, role FROM users WHERE username = ?", (username,)).fetchone()
        if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
            return result[1]  # Return the user's role if password is correct.
        return None

def fetch_patients(username, role):
    """Fetches a list of patients visible to the current user based on their role and class."""
    with sqlite3.connect('medical_records.db') as conn:
        if role == 'admin':
            # Admins can see all patients.
            return pd.read_sql_query("SELECT patient_id, patient_name, dob_or_age FROM patients", conn)
        else:
            # Students see patients they created AND patients shared with their class(es).
            cursor = conn.cursor()
            class_ids = [row[0] for row in cursor.execute("SELECT uce.class_id FROM user_class_enrollment uce JOIN users u ON u.id = uce.user_id WHERE u.username = ?", (username,)).fetchall()]
            query = "SELECT DISTINCT p.patient_id, p.patient_name, p.dob_or_age FROM patients p LEFT JOIN patient_class_permissions pcp ON p.patient_id = pcp.patient_id WHERE p.created_by_user = 'admin' OR p.created_by_user = ?"
            params = [username]
            if class_ids:
                placeholders = ','.join(['?'] * len(class_ids))
                query += f" OR pcp.class_id IN ({placeholders})"
                params.extend(class_ids)
            return pd.read_sql_query(query, conn, params=params)

def delete_document(document_id):
    """Deletes a document, its comments, and any associated uploaded file from the server."""
    with sqlite3.connect('medical_records.db') as conn:
        cursor = conn.cursor()
        result = cursor.execute("SELECT document_type, data FROM documents WHERE id = ?", (document_id,)).fetchone()
        if result:
            doc_type, doc_data_json = result
            # If it's a PDF, delete the file from the 'uploads' folder.
            if doc_type == "PDF Upload":
                doc_data = json.loads(doc_data_json)
                filename = doc_data.get('filename')
                if filename:
                    try: os.remove(os.path.join(UPLOAD_DIRECTORY, filename))
                    except OSError as e: print(f"Error deleting file: {e}")
            # Cascade delete: remove comments associated with the document first.
            cursor.execute("DELETE FROM comments WHERE document_id = ?", (document_id,))
            cursor.execute("DELETE FROM documents WHERE id = ?", (document_id,))
        conn.commit()

def update_comment(comment_id, new_text):
    """Updates the text of an existing comment."""
    with sqlite3.connect('medical_records.db') as conn:
        conn.cursor().execute("UPDATE comments SET comment_text = ? WHERE id = ?", (new_text, comment_id)); conn.commit()

def delete_comment(comment_id):
    """Deletes a specific comment from the database."""
    with sqlite3.connect('medical_records.db') as conn:
        conn.cursor().execute("DELETE FROM comments WHERE id = ?", (comment_id,)); conn.commit()

def fetch_comments(document_id):
    """Retrieves all comments for a given document, ordered by creation time."""
    with sqlite3.connect('medical_records.db') as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.cursor().execute("SELECT id, username, comment_text, strftime('%Y-%m-%d %H:%M', created_at) as created_at FROM comments WHERE document_id = ? ORDER BY created_at ASC", (document_id,)).fetchall()]

def fetch_single_comment(comment_id):
    """Retrieves the text of a single comment, used for pre-filling the edit modal."""
    with sqlite3.connect('medical_records.db') as conn:
        result = conn.cursor().execute("SELECT comment_text FROM comments WHERE id = ?", (comment_id,)).fetchone()
        return result[0] if result else None

def add_comment(document_id, username, comment_text):
    """Adds a new comment to a document."""
    with sqlite3.connect('medical_records.db') as conn:
        conn.cursor().execute("INSERT INTO comments (document_id, username, comment_text) VALUES (?, ?, ?)", (document_id, username, comment_text)); conn.commit()

def create_patient(name, dob, contact, insurance, username):
    """Creates a new patient record with a unique, randomly generated ID."""
    with sqlite3.connect('medical_records.db') as conn:
        new_patient_id = secrets.token_hex(4)
        conn.cursor().execute("INSERT INTO patients (patient_id, patient_name, dob_or_age, contact_info, insurance_details, created_by_user) VALUES (?, ?, ?, ?, ?, ?)", (new_patient_id, name, dob, contact, insurance, username)); conn.commit()
        return new_patient_id

def create_document(patient_id, doc_type, doc_date, data_dict, username):
    """Creates a new document record, storing form data as a JSON string."""
    with sqlite3.connect('medical_records.db') as conn:
        data_dict['edit_history'] = [] # Initialize edit history
        conn.cursor().execute("INSERT INTO documents (patient_id, document_type, document_date, data, created_by_user) VALUES (?, ?, ?, ?, ?)", (patient_id, doc_type, doc_date, json.dumps(data_dict, indent=4), username)); conn.commit()

def update_document(document_id, new_data_dict, editor_username):
    """Updates an existing document, adding an entry to its edit history."""
    with sqlite3.connect('medical_records.db') as conn:
        cursor = conn.cursor()
        result = cursor.execute("SELECT data FROM documents WHERE id = ?", (document_id,)).fetchone()
        if not result: return
        existing_data = json.loads(result[0])
        # Create a log entry for this edit.
        edit_log_entry = {'edited_by': editor_username, 'edited_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        existing_data.setdefault('edit_history', []).append(edit_log_entry)
        new_data_dict['edit_history'] = existing_data['edit_history']
        cursor.execute("UPDATE documents SET data = ? WHERE id = ?", (json.dumps(new_data_dict, indent=4), document_id)); conn.commit()

def fetch_patient_info(patient_id):
    """Retrieves all details for a single patient."""
    with sqlite3.connect('medical_records.db') as conn:
        df = pd.read_sql_query("SELECT * FROM patients WHERE patient_id = ?", conn, params=(patient_id,))
        return df.iloc[0].to_dict() if not df.empty else {}

def fetch_patient_documents(patient_id, username, role):
    """Retrieves a list of all documents for a single patient."""
    with sqlite3.connect('medical_records.db') as conn:
        return pd.read_sql_query("SELECT id, document_type, document_date FROM documents WHERE patient_id = ? ORDER BY document_date ASC", conn, params=(patient_id,))

def fetch_single_document(document_id):
    """Retrieves the details of a single document, parsing its JSON data."""
    with sqlite3.connect('medical_records.db') as conn:
        result = conn.cursor().execute("SELECT document_type, data, created_by_user FROM documents WHERE id = ?", (document_id,)).fetchone()
        if not result: return None, None, None
        return result[0], json.loads(result[1]), result[2]

# --- 2. DASH APP INITIALIZATION ---
# Initialize the Dash app.
app = dash.Dash(__name__,
                suppress_callback_exceptions=True,  # Necessary for multi-page apps where components are not in the initial layout.
                title="Patient Records",
                external_stylesheets=[dbc.themes.BOOTSTRAP]) # Use Bootstrap for styling.
server = app.server  # Expose the Flask server for deployment.

# --- 3. LAYOUT DEFINITIONS ---
# This section defines the HTML structure and components for each page of the app.

# Reusable style definitions for input components.
input_style = {'width': '100%', 'marginBottom': '10px'}
textarea_style = {'width': '100%', 'height': 120, 'marginBottom': '10px'}
upload_style = {'width': '100%', 'height': '60px', 'lineHeight': '60px', 'borderWidth': '1px', 'borderStyle': 'dashed', 'borderRadius': '5px', 'textAlign': 'center', 'margin': '10px 0'}

# Layout for the login page.
login_layout = html.Div([
    html.H2("Login", style={'textAlign': 'center'}),
    html.Div(id='login-error-msg', style={'color': 'red', 'marginBottom': '10px', 'textAlign': 'center'}),
    html.Div(id='login-success-msg', style={'color': 'green', 'marginBottom': '10px', 'textAlign': 'center'}),
    dcc.Input(id='login-username', placeholder='Username', style=input_style),
    dcc.Input(id='login-password', type='password', placeholder='Password', style=input_style),
    html.Button('Login', id='login-button', n_clicks=0, className="btn btn-primary w-100"),
    html.Br(),
    html.P(["New user? ", dcc.Link("Register", href="/register")], style={'marginTop': '10px'})
], style={'maxWidth': '400px', 'margin': 'auto', 'padding': '20px'})

# Layout for the registration page. It's a function to dynamically populate the class dropdown.
def register_layout():
    class_options = [{'label': c['class_name'], 'value': c['id']} for c in get_classes()]
    return html.Div([
        html.H2("Register", style={'textAlign': 'center'}),
        html.Div(id='register-error-msg', style={'color': 'red', 'marginBottom': '10px', 'textAlign': 'center'}),
        dcc.Input(id='register-username', placeholder='Username', style=input_style),
        dcc.Input(id='register-password', type='password', placeholder='Password', style=input_style),
        html.Label("Role"),
        dcc.Dropdown(id='register-role', options=['student', 'admin'], value='student', style=input_style),
        html.Div(id='class-dropdown-div', children=[
            html.Label("Class(es)"),
            dcc.Dropdown(id='register-class', options=class_options, placeholder="Select one or more classes...", style=input_style, multi=True)
        ]),
        html.Button('Register', id='register-button', n_clicks=0, className="btn btn-primary w-100"),
        html.Br(),
        html.P([dcc.Link("Back to Login", href="/login")], style={'marginTop': '10px'})
    ], style={'maxWidth': '400px', 'margin': 'auto', 'padding': '20px'})

# The main application layout. It acts as a container for all other pages.
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),  # Manages the URL in the browser's address bar.
    dcc.Store(id='user-session', storage_type='session'),  # Stores session data (e.g., username) in the browser.
    dcc.Store(id='message-store', storage_type='session'), # Stores temporary messages (e.g., "Registration successful").
    html.Div(id='header', children=[
        html.Span(id='user-status', style={'marginRight': '20px'}),
        dcc.Link(html.Button('Admin', id='admin-button', className="btn btn-info me-2", style={'display': 'none'}), href='/admin'),
        html.Button('Logout', id='logout-button', n_clicks=0, className="btn btn-secondary", style={'display': 'none'})
    ], style={'textAlign': 'right', 'padding': '10px', 'borderBottom': '1px solid #ddd'}),
    dbc.Container(id='page-content', className="mt-4") # The content of the current page will be rendered here.
])

# Layout for the main patient lookup page.
main_lookup_layout = html.Div([
    html.H2("Patient Lookup"),
    html.Button('Add New Patient', id='add-patient-button', n_clicks=0, className="btn btn-primary", style={'marginBottom': '10px'}),
    # Modal popup for adding a new patient.
    dbc.Modal([
        dbc.ModalHeader("Add New Patient"),
        dbc.ModalBody([
            html.Div(id='new-patient-error-msg', style={'color': 'red', 'marginBottom': '10px'}),
            html.Label("Patient Name*"), dcc.Input(id='new-patient-name', style=input_style),
            html.Label("Date of Birth or Age*"), dcc.Input(id='new-patient-dob', style=input_style),
            html.Label("Contact Information"), dcc.Input(id='new-patient-contact', style=input_style),
            html.Label("Insurance Details"), dcc.Input(id='new-patient-insurance', style=input_style)
        ]),
        dbc.ModalFooter(dbc.Button("Submit", id="submit-new-patient-button", n_clicks=0))
    ], id="new-patient-modal", is_open=False),
    html.Button('Refresh Data', id='refresh-button', n_clicks=0, className="btn btn-secondary", style={'marginBottom': '10px', 'marginLeft': '10px'}),
    html.Div(id='new-patient-output-msg', style={'color': 'green', 'marginTop': '10px'}),
    dash_table.DataTable(id='patient-table',
                         columns=[{"name": i, "id": i} for i in ['patient_id', 'patient_name', 'dob_or_age']],
                         data=[], row_selectable="single", page_size=15, style_table={'overflowX': 'auto'})
])

# Layout for the patient detail page. This is a function to dynamically generate the layout for a specific patient.
def patient_detail_layout(patient_id, session_data):
    patient_info = fetch_patient_info(patient_id)
    if not patient_info: return html.Div([html.H2("Error: Patient Not Found"), dcc.Link("Go back", href="/")])

    # Conditionally render the sharing panel only if the user is an admin.
    admin_sharing_panel = []
    if session_data.get('role') == 'admin':
        class_options = [{'label': c['class_name'], 'value': c['id']} for c in get_classes()]
        admin_sharing_panel = [
            html.Hr(),
            dbc.Card([
                dbc.CardHeader("Sharing Settings (Admin)"),
                dbc.CardBody([
                    dbc.RadioItems(id='sharing-mode-radio', options=[
                        {'label': 'Private (share with no one)', 'value': 'private'},
                        {'label': 'Share with All Classes', 'value': 'all'},
                        {'label': 'Custom (select from list)', 'value': 'custom'},
                    ], value='private', className="mb-3"),
                    dcc.Dropdown(id='share-class-dropdown', options=class_options, multi=True, placeholder="Select classes to share with..."),
                    html.Button("Save Sharing Settings", id="save-sharing-btn", className="btn btn-success mt-3"),
                    html.Div(id='sharing-save-status', className="mt-2")
                ])
            ], className="mt-4")
        ]
    
    return html.Div([
        # Hidden stores for holding state related to this page.
        dcc.Store(id='viewed-document-store'),
        dcc.Store(id='comment-edit-store'),
        # Modals for various actions on this page.
        dbc.Modal([dbc.ModalHeader("Edit Comment"), dbc.ModalBody(dbc.Textarea(id='edit-comment-textarea', style={'height': '150px'})), dbc.ModalFooter(dbc.Button("Save Changes", id="save-comment-button", color="primary"))], id="edit-comment-modal", is_open=False),
        dbc.Modal([dbc.ModalHeader("Upload PDF Document"), dbc.ModalBody([html.Div(id='upload-pdf-error-msg', style={'color': 'red', 'marginBottom': '10px'}), dbc.Label("Document Display Name*", html_for="upload-pdf-display-name"), dbc.Input(id="upload-pdf-display-name", placeholder="e.g., 'Initial Referral Letter'", style={'marginBottom': '15px'}), dcc.Upload(id='upload-pdf-component', children=html.Div(['Drag and Drop or ', html.A('Select a PDF')]), style=upload_style, multiple=False), html.Div(id='pdf-filename-output')]), dbc.ModalFooter(dbc.Button("Submit Upload", id="submit-upload-pdf-button", color="primary"))], id="upload-pdf-modal", is_open=False),
        dbc.Modal([dbc.ModalHeader("Confirm Deletion"), dbc.ModalBody("Are you sure you want to permanently delete this document and all its comments? This action cannot be undone."), dbc.ModalFooter(dbc.Button("Confirm Delete", id="confirm-delete-doc-button", color="danger"))], id="delete-doc-confirm-modal", is_open=False),
        
        # Main content of the patient detail page.
        html.H2(f"Records for: {patient_info.get('patient_name')}"),
        html.P(f"DOB: {patient_info.get('dob_or_age')} | Contact: {patient_info.get('contact_info')} | Insurance: {patient_info.get('insurance_details')}"),
        dcc.Link('Back to Patient Lookup', href='/', className="btn btn-link"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                html.H3("Create New Document"),
                dcc.Link('New Evaluation Note', href=f'/new-doc?type=evaluation&patient_id={patient_id}', style={'display':'block'}),
                dcc.Link('New Treatment Note', href=f'/new-doc?type=treatment&patient_id={patient_id}', style={'display':'block'}),
                dcc.Link('New Discharge Summary', href=f'/new-doc?type=discharge&patient_id={patient_id}', style={'display':'block'}),
                html.Hr(),
                dbc.Button("Upload PDF", id="open-upload-pdf-modal-btn", color="secondary", className="mt-2"),
                *admin_sharing_panel # Unpack the admin panel list here.
            ], width=4),
            dbc.Col([
                html.H3("Existing Documents"),
                dash_table.DataTable(id='document-table', columns=[{"name": i, "id": i} for i in ['id', 'document_type', 'document_date']], data=[], row_selectable="single")
            ], width=8)
        ]),
        dbc.Row([
            dbc.Col(html.Div(id='document-viewer-output', style={'marginTop': '20px', 'padding': '15px', 'border': '1px solid #ddd', 'backgroundColor': '#f9f9f9', 'borderRadius': '5px', 'minHeight': '200px'}), width=6),
            dbc.Col(html.Div(id='comment-section', style={'marginTop': '20px'}), width=6)
        ])
    ])

# Layout for the admin management page.
def admin_management_layout():
    return html.Div([
        html.H2("Admin Management"),
        dcc.Link("Back to Patient Lookup", href="/"),
        html.Hr(),
        dbc.Row([
            # Column for managing classes.
            dbc.Col([
                dbc.Card([dbc.CardHeader("Create New Class"), dbc.CardBody([dcc.Input(id='new-class-name', placeholder="Enter class name...", style=input_style), html.Button("Create Class", id="create-class-btn", className="btn btn-primary"), html.Div(id='create-class-status', className="mt-2")])], className="mb-4"),
                dbc.Card([dbc.CardHeader("Existing Classes and Students"), dbc.CardBody(id='class-list-container', children=[dbc.Alert("Loading classes...", color="info")])])
            ], width=4),
            # Column for managing student accounts and enrollments.
            dbc.Col([
                dbc.Card([dbc.CardHeader("Manage Student Accounts"), dbc.CardBody(id='student-management-container', children=[dbc.Alert("Loading students...", color="info")])])
            ], width=8)
        ])
    ])

# Helper function to create styled sections for the forms.
def create_form_section(title, children):
    return html.Div([html.H4(title), *children], style={'border': '1px solid #eee', 'padding': '10px', 'marginBottom': '15px', 'borderRadius': '5px'})

# --- Form Layouts (Evaluation, Treatment, Discharge) ---
# Each function generates a form, pre-filling data if a document ID is provided (edit mode).

def evaluation_layout(patient_info, doc_id=None, doc_data=None):
    doc_data, mode = doc_data or {}, "Edit" if doc_id else "New"
    button_text = "Save Changes" if doc_id else "Submit Evaluation"
    return html.Div([
        html.H2(f"{mode} Evaluation for: {patient_info.get('patient_name')}"),
        dcc.Store(id='current-patient-id', data=patient_info.get('patient_id')),
        dcc.Store(id='current-document-id', data=doc_id),
        create_form_section("Session Details", [html.Label("Date and Time of Service*"), dcc.DatePickerSingle(id='eval-date', date=doc_data.get('document_date', datetime.now().date()), style=input_style), html.Label("Referring Physician"), dcc.Input(id='eval-physician', value=doc_data.get('Referring Physician'), style=input_style), html.Label("Diagnosis/ICD 10 Code(s)"), dcc.Input(id='eval-diag-codes', value=doc_data.get('Diagnosis Codes'), style=input_style)]),
        create_form_section("Subjective Notes", [dcc.Textarea(id='eval-subjective', value=doc_data.get('Subjective Notes'), placeholder="History, Occupational Profile...", style=textarea_style)]),
        create_form_section("Objective Notes", [dcc.Textarea(id='eval-objective', value=doc_data.get('Objective Notes'), placeholder="Observations, Measurements...", style=textarea_style)]),
        create_form_section("Assessment", [html.Label("Problem Statement"), dcc.Textarea(id='eval-problem', value=doc_data.get('Problem Statement'), style=textarea_style), html.Label("Potential for Rehabilitation:"), dcc.RadioItems(id='eval-rehab-potential', value=doc_data.get('Rehab Potential'), options=['Excellent', 'Good', 'Fair', 'Poor'], labelStyle={'display': 'inline-block', 'margin-right': '10px'})]),
        create_form_section("Plan", [html.Label("Goals (Long-Term and Short-Term)"), dcc.Textarea(id='eval-goals', value=doc_data.get('Goals'), style=textarea_style), html.Label("Detailed Plan of Care"), dcc.Textarea(id='eval-plan', value=doc_data.get('Plan of Care'), style=textarea_style), html.Label("Recommended Frequency & Duration"), dcc.Input(id='eval-frequency', value=doc_data.get('Frequency'), type='text', style=input_style)]),
        html.Button(button_text, id='submit-eval-button', n_clicks=0, className="btn btn-success", style={'marginTop': '20px'}),
        html.Div(id='output-form-message')
    ])

def treatment_layout(patient_info, doc_id=None, doc_data=None):
    doc_data, mode = doc_data or {}, "Edit" if doc_id else "New"
    button_text = "Save Changes" if doc_id else "Submit Treatment Note"
    return html.Div([
        html.H2(f"{mode} Treatment Note for: {patient_info.get('patient_name')}"),
        dcc.Store(id='current-patient-id', data=patient_info.get('patient_id')),
        dcc.Store(id='current-document-id', data=doc_id),
        create_form_section("Session Details", [html.Label("Date and Time of Service*"), dcc.DatePickerSingle(id='treat-date', date=doc_data.get('document_date', datetime.now().date()), style=input_style), html.Label("Service Duration (minutes)"), dcc.Input(id='treat-duration', value=doc_data.get('Service Duration'), type='number', style=input_style)]),
        create_form_section("Subjective Notes", [dcc.Textarea(id='treat-subjective', value=doc_data.get('Subjective Notes'), placeholder="Client's Account, Concerns, Pain...", style=textarea_style)]),
        create_form_section("Objective Notes", [dcc.Textarea(id='treat-objective', value=doc_data.get('Objective Notes'), placeholder="Interventions performed, observations...", style=textarea_style)]),
        create_form_section("Assessment", [html.Label("Progress Toward Goals:"), dcc.RadioItems(id='treat-progress', value=doc_data.get('Progress Toward Goals'), options=['Improved', 'No Change', 'Regression'], labelStyle={'display': 'inline-block', 'margin-right': '10px'}), html.Label("Updated Goals (if any)"), dcc.Textarea(id='treat-goals', value=doc_data.get('Updated Goals'), style=textarea_style)]),
        create_form_section("Plan", [html.Label("Plan for Next Session"), dcc.Textarea(id='treat-plan', value=doc_data.get('Plan for Next Session'), style=textarea_style), html.Label("Patient Education Provided"), dcc.Textarea(id='treat-education', value=doc_data.get('Patient Education'), placeholder="e.g., Home Exercise Program (HEP)", style=textarea_style)]),
        html.Button(button_text, id='submit-treat-button', n_clicks=0, className="btn btn-success", style={'marginTop': '20px'}),
        html.Div(id='output-form-message')
    ])

def discharge_layout(patient_info, doc_id=None, doc_data=None):
    doc_data, mode = doc_data or {}, "Edit" if doc_id else "New"
    button_text = "Save Changes" if doc_id else "Submit Discharge Summary"
    return html.Div([
        html.H2(f"{mode} Discharge Summary for: {patient_info.get('patient_name')}"),
        dcc.Store(id='current-patient-id', data=patient_info.get('patient_id')),
        dcc.Store(id='current-document-id', data=doc_id),
        create_form_section("Session Details", [html.Label("Date of Discharge*"), dcc.DatePickerSingle(id='dis-date', date=doc_data.get('document_date', datetime.now().date()), style=input_style)]),
        create_form_section("Summary of Care", [dcc.Textarea(id='dis-summary', value=doc_data.get('Summary of Care'), placeholder="Summary of interventions, progress...", style=textarea_style)]),
        create_form_section("Goals", [html.Label("Status of Goals at Discharge"), dcc.Textarea(id='dis-goals', value=doc_data.get('Goal Status at Discharge'), placeholder="e.g., LTG 1: Met...", style=textarea_style)]),
        create_form_section("Reason for Discharge (mark all that apply)", [dcc.Checklist(id='dis-reason', value=doc_data.get('Reason for Discharge', []), options=[{'label': 'Client has achieved all goals.', 'value': 'goals_met'}, {'label': 'Client achieved maximum benefit.', 'value': 'max_benefit'}, {'label': 'Client desires to discontinue.', 'value': 'client_desire'}, {'label': 'Client is no longer able to participate.', 'value': 'unable_to_participate'}], labelStyle={'display': 'block'}), dcc.Input(id='dis-reason-custom', placeholder="Custom reason...", style=input_style)]),
        create_form_section("Discharge Plan", [dcc.Textarea(id='dis-plan', value=doc_data.get('Discharge Plan'), placeholder="Follow-up instructions, recommendations...", style=textarea_style)]),
        html.Button(button_text, id='submit-dis-button', n_clicks=0, className="btn btn-success", style={'marginTop': '20px'}),
        html.Div(id='output-form-message')
    ])

# --- 4. CALLBACKS ---
# This is where the application's interactivity and logic are defined.
# Each function decorated with @app.callback is a callback.

@server.route("/download/<path:filename>")
def download_file(filename):
    """
    Creates a Flask route to allow users to download files from the UPLOAD_DIRECTORY.
    This is necessary because Dash doesn't have a built-in component for direct file serving.
    """
    return flask.send_from_directory(UPLOAD_DIRECTORY, filename, as_attachment=True)

@app.callback(
    Output('class-dropdown-div', 'style'),
    Input('register-role', 'value')
)
def toggle_class_dropdown(role):
    """Shows or hides the class selection dropdown on the registration page based on the selected role."""
    return {'display': 'block'} if role == 'student' else {'display': 'none'}

@app.callback(
    Output('login-success-msg', 'children'),
    Output('message-store', 'data', allow_duplicate=True),
    Input('page-content', 'children'),
    State('message-store', 'data'),
    prevent_initial_call=True
)
def display_login_messages(layout, data):
    """
    Displays a "flash" message (e.g., after successful registration) on the login page
    and then clears the message from the store.
    """
    if data and 'message' in data:
        return data['message'], {} # Display message and clear store
    return "", no_update

@app.callback(
    Output('url', 'href'),
    Input('patient-table', 'active_cell'),
    State('patient-table', 'data'),
    prevent_initial_call=True
)
def go_to_patient_detail(cell, data):
    """Navigates to the patient detail page when a user clicks a row in the patient table."""
    if cell:
        patient_id = data[cell['row']]['patient_id']
        return f"/patient-detail?patient_id={patient_id}"
    return no_update

@app.callback(
    Output("delete-doc-confirm-modal", "is_open"),
    [Input("delete-doc-btn", "n_clicks"), Input("confirm-delete-doc-button", "n_clicks")],
    State("delete-doc-confirm-modal", "is_open"),
    prevent_initial_call=True
)
def toggle_delete_doc_modal(n_del, n_conf, is_open):
    """Opens and closes the 'confirm deletion' modal for documents."""
    return not is_open if n_del or n_conf else is_open

@app.callback(
    Output("upload-pdf-modal", "is_open"),
    [Input("open-upload-pdf-modal-btn", "n_clicks"), Input("submit-upload-pdf-button", "n_clicks")],
    State("upload-pdf-modal", "is_open"),
    prevent_initial_call=True
)
def toggle_pdf_modal(n1, n2, is_open):
    """Opens and closes the PDF upload modal."""
    return not is_open if n1 or n2 else is_open

@app.callback(
    Output('pdf-filename-output', 'children'),
    Input('upload-pdf-component', 'filename'),
    prevent_initial_call=True
)
def update_filename_output(filename):
    """Displays the name of the selected file in the PDF upload modal."""
    return f"Selected: {filename}" if filename else ""

@app.callback(
    Output('upload-pdf-display-name', 'value'),
    Output('pdf-filename-output', 'children', allow_duplicate=True),
    Output('upload-pdf-error-msg', 'children'),
    Input('upload-pdf-modal', 'is_open'),
    prevent_initial_call=True
)
def clear_upload_form(is_open):
    """Resets the PDF upload form fields when the modal is opened."""
    return "", "", "" if is_open else no_update

@app.callback(
    Output('page-content', 'children'),
    Input('url', 'pathname'),
    State('url', 'search'),
    State('user-session', 'data')
)
def render_page_content(pathname, search, session_data):
    """
    This is the main router of the app. It reads the URL and returns the
    appropriate page layout. It also handles authentication and authorization.
    """
    session_data = session_data or {}
    is_logged_in = 'username' in session_data and session_data.get('username')

    # If user is not logged in, show login/register page.
    if not is_logged_in:
        return register_layout() if pathname == '/register' else login_layout

    # Route to different pages based on the URL pathname.
    if pathname == '/admin':
        if session_data.get('role') == 'admin':
            return admin_management_layout()
        else:
            return html.Div(["Access Denied.", dcc.Link("Go back home", href="/")])
    elif pathname == '/patient-detail':
        patient_id = parse_qs(urlparse(search).query).get('patient_id', [None])[0]
        return patient_detail_layout(patient_id, session_data) if patient_id else main_lookup_layout
    elif pathname == '/new-doc' or pathname == '/edit-doc':
        params = parse_qs(urlparse(search).query)
        doc_id = params.get('doc_id', [None])[0]
        # Handle editing an existing document.
        if doc_id: 
            doc_type, doc_data, creator = fetch_single_document(doc_id)
            # Check if the user has permission to edit.
            can_edit = session_data.get('role') == 'admin' or session_data.get('username') == creator
            if not can_edit: return html.Div(["Access Denied.", dcc.Link("Go back", href="/")])
            with sqlite3.connect('medical_records.db') as conn: p_id = conn.execute("SELECT patient_id FROM documents WHERE id = ?", (doc_id,)).fetchone()[0]
            patient_info = fetch_patient_info(p_id)
            if doc_type == 'Evaluation': return evaluation_layout(patient_info, doc_id, doc_data)
            if doc_type == 'Treatment': return treatment_layout(patient_info, doc_id, doc_data)
            if doc_type == 'Discharge': return discharge_layout(patient_info, doc_id, doc_data)
        # Handle creating a new document.
        else: 
            patient_id, doc_type = params.get('patient_id', [None])[0], params.get('type', [None])[0]
            if patient_id and doc_type:
                patient_info = fetch_patient_info(patient_id)
                if doc_type == 'evaluation': return evaluation_layout(patient_info)
                if doc_type == 'treatment': return treatment_layout(patient_info)
                if doc_type == 'discharge': return discharge_layout(patient_info)
    
    # Default to the main patient lookup page.
    return main_lookup_layout

@app.callback(
    Output('url', 'pathname', allow_duplicate=True),
    Output('register-error-msg', 'children'),
    Output('message-store', 'data'),
    Input('register-button', 'n_clicks'),
    [State('register-username', 'value'), State('register-password', 'value'), 
     State('register-role', 'value'), State('register-class', 'value')],
    prevent_initial_call=True
)
def handle_registration(n, u, p, r, c_ids):
    """Handles the user registration form submission."""
    if not u or not p: return no_update, "Username and password are required.", no_update
    if r == 'student' and not c_ids: return no_update, "Students must select at least one class.", no_update
    try:
        create_user(u, p, r, c_ids)
        # On success, redirect to login page with a success message.
        return '/login', "", {'message': "Registration successful! Please login."}
    except sqlite3.IntegrityError:
        return no_update, "Error: Username already exists.", no_update

@app.callback(
    Output('user-status', 'children'),
    Output('logout-button', 'style'),
    Output('admin-button', 'style'),
    Output('user-session', 'data', allow_duplicate=True),
    Output('url', 'pathname', allow_duplicate=True),
    Input('user-session', 'data'),
    Input('logout-button', 'n_clicks'),
    prevent_initial_call=True
)
def handle_session_status(session, n_clicks):
    """
    Manages the header content based on login status.
    Shows user info and logout/admin buttons if logged in.
    Handles the logout process.
    """
    if ctx.triggered_id == 'logout-button':
        # Clear session data and redirect to login page.
        return "", {'display': 'none'}, {'display': 'none'}, {}, '/login'
    
    if session and 'username' in session:
        user_info = f"Logged in as: {session['username']} ({session['role']})"
        logout_style = {'display': 'inline-block'}
        admin_style = {'display': 'inline-block'} if session.get('role') == 'admin' else {'display': 'none'}
        return user_info, logout_style, admin_style, no_update, no_update
    
    return "", {'display': 'none'}, {'display': 'none'}, no_update, no_update

@app.callback(
    Output('user-session', 'data', allow_duplicate=True),
    Output('url', 'pathname', allow_duplicate=True),
    Output('login-error-msg', 'children'),
    Input('login-button', 'n_clicks'),
    State('login-username', 'value'),
    State('login-password', 'value'),
    prevent_initial_call=True
)
def handle_login(n, u, p):
    """Handles the login form submission."""
    if not u or not p: return no_update, no_update, "Username and password are required."
    role = verify_user(u, p)
    if role:
        # If credentials are valid, store user data in session and redirect to main page.
        return {'username': u, 'role': role}, '/', ""
    else:
        return no_update, no_update, "Invalid username or password."

# --- Admin Page Callbacks ---

@app.callback(
    Output('create-class-status', 'children'),
    Input('create-class-btn', 'n_clicks'),
    State('new-class-name', 'value'),
    prevent_initial_call=True
)
def handle_create_class(n, class_name):
    """Handles the 'Create Class' button click on the admin page."""
    if not class_name: return dbc.Alert("Please enter a class name.", color="danger")
    try:
        create_class(class_name)
        return dbc.Alert(f"Class '{class_name}' created.", color="success", duration=4000)
    except sqlite3.IntegrityError:
        return dbc.Alert(f"Error: Class '{class_name}' already exists.", color="danger")

@app.callback(
    Output('class-list-container', 'children'),
    [Input('create-class-status', 'children'), 
     Input('url', 'pathname'), 
     Input({'type': 'student-class-dropdown', 'index': ALL}, 'value')],
    State('user-session', 'data')
)
def populate_class_list(status, pathname, dropdown_vals, session):
    """Populates the list of classes and their enrolled students on the admin page."""
    if not (session and session.get('role') == 'admin' and pathname == '/admin'): return no_update
    classes_with_students = get_classes_with_students()
    if not classes_with_students: return html.P("No classes created yet.")
    
    # Create an accordion view to display classes and students.
    accordion_items = []
    for class_name, students in sorted(classes_with_students.items()):
        student_list = [html.Li(s) for s in students if s] if any(students) else [html.Em("No students enrolled.")]
        item = dbc.AccordionItem(children=html.Ul(student_list), title=f"{class_name} ({len([s for s in students if s])} students)")
        accordion_items.append(item)
    return dbc.Accordion(accordion_items, start_collapsed=True, always_open=True)

@app.callback(
    Output('student-management-container', 'children'),
    Input('url', 'pathname'),
    State('user-session', 'data')
)
def populate_student_management_list(pathname, session):
    """Populates the student management panel on the admin page with dropdowns to assign classes."""
    if not (session and session.get('role') == 'admin' and pathname == '/admin'): return no_update
    all_users, all_classes = get_all_users(), get_classes()
    class_options = [{'label': c['class_name'], 'value': c['id']} for c in all_classes]
    student_rows = [html.H5("Students")]
    for user in all_users:
        if user['role'] == 'student':
            # Create a row for each student with a multi-select dropdown for their classes.
            student_rows.append(dbc.Row([
                dbc.Col(html.B(user['username']), width=3),
                dbc.Col(dcc.Dropdown(id={'type': 'student-class-dropdown', 'index': user['username']}, 
                                     options=class_options, value=user['class_ids'], clearable=False, multi=True), width=6),
                dbc.Col(html.Div(id={'type': 'student-class-update-status', 'index': user['username']}), width=3)
            ], align="center", className="mb-2"))
    return student_rows

@app.callback(
    Output({'type': 'student-class-update-status', 'index': MATCH}, 'children'),
    Input({'type': 'student-class-dropdown', 'index': MATCH}, 'value'),
    State({'type': 'student-class-dropdown', 'index': MATCH}, 'id'),
    prevent_initial_call=True
)
def update_student_classes_assignment(new_class_ids, dropdown_id):
    """
    A pattern-matching callback that triggers when ANY student's class dropdown is changed.
    It updates the student's class enrollment in the database.
    'MATCH' ensures this callback responds to the specific dropdown that was changed.
    """
    update_user_classes(dropdown_id['index'], new_class_ids)
    return dbc.Alert("Updated!", color="success", duration=2000, style={'padding': '0.5rem', 'margin-bottom': '0'})

# --- Patient Sharing Callbacks (Admin only) ---

@app.callback(
    Output('sharing-mode-radio', 'value'),
    Output('share-class-dropdown', 'value'),
    Input('url', 'pathname'),
    State('url', 'search'),
    prevent_initial_call=True
)
def set_initial_sharing_state(pathname, search):
    """When the patient detail page loads, this sets the sharing controls to reflect the current settings."""
    if pathname != '/patient-detail': return no_update, no_update
    patient_id = parse_qs(urlparse(search).query).get('patient_id', [None])[0]
    if not patient_id: return no_update, no_update
    
    all_classes = get_classes()
    shared_with = get_shared_classes_for_patient(patient_id)
    
    # Determine the mode ('private', 'all', 'custom') based on which classes are shared.
    if not shared_with: mode = 'private'
    elif len(shared_with) == len(all_classes): mode = 'all'
    else: mode = 'custom'
    
    return mode, shared_with

@app.callback(
    Output('share-class-dropdown', 'value', allow_duplicate=True),
    Output('share-class-dropdown', 'disabled'),
    Input('sharing-mode-radio', 'value'),
    prevent_initial_call=True
)
def control_sharing_dropdown(mode):
    """Enables/disables and updates the class selection dropdown based on the selected sharing mode."""
    if mode == 'private':
        return [], True # Clear selection and disable
    if mode == 'all':
        all_classes_ids = [c['id'] for c in get_classes()]
        return all_classes_ids, True # Select all and disable
    if mode == 'custom':
        return no_update, False # Enable without changing selection
    return no_update, True

@app.callback(
    Output('sharing-save-status', 'children'),
    Input('save-sharing-btn', 'n_clicks'),
    [State('sharing-mode-radio', 'value'),
     State('share-class-dropdown', 'value'), 
     State('url', 'search')],
    prevent_initial_call=True
)
def save_sharing_settings(n, mode, selected_classes, search):
    """Saves the patient sharing settings to the database when the 'Save' button is clicked."""
    patient_id = parse_qs(urlparse(search).query).get('patient_id', [None])[0]
    if not patient_id: return dbc.Alert("Error: Patient ID not found.", color="danger")

    if mode == 'private': class_ids_to_save = []
    elif mode == 'all': class_ids_to_save = [c['id'] for c in get_classes()]
    else: class_ids_to_save = selected_classes
    
    update_patient_sharing(patient_id, class_ids_to_save)
    return dbc.Alert("Sharing settings saved!", color="success", duration=4000)

# --- Data Loading and Patient Modal Callbacks ---

@app.callback(
    Output('patient-table', 'data'),
    [Input('page-content', 'children'), Input('refresh-button', 'n_clicks')],
    [State('user-session', 'data')],
    prevent_initial_call=True
)
def load_main_table(content, n_clicks, session):
    """Loads or refreshes the data in the main patient lookup table."""
    if session and 'username' in session:
        # Check if the current page is the main patient lookup page.
        is_main_page = isinstance(content, dict) and any(c.get('props', {}).get('id') == 'patient-table' for c in content.get('props', {}).get('children', []))
        if ctx.triggered_id == 'refresh-button' or is_main_page:
            return fetch_patients(session['username'], session['role']).to_dict('records')
    return no_update

@app.callback(
    Output('new-patient-modal', 'is_open'),
    Output('patient-table', 'data', allow_duplicate=True),
    Output('new-patient-output-msg', 'children'),
    Output('new-patient-error-msg', 'children'),
    [Input('add-patient-button', 'n_clicks'), Input('submit-new-patient-button', 'n_clicks')],
    [State('new-patient-modal', 'is_open'), State('new-patient-name', 'value'), 
     State('new-patient-dob', 'value'), State('new-patient-contact', 'value'), 
     State('new-patient-insurance', 'value'), State('user-session', 'data')],
    prevent_initial_call=True
)
def handle_patient_modal(add, sub, is_open, name, dob, con, ins, session):
    """Manages the 'Add New Patient' modal and form submission."""
    if ctx.triggered_id == 'add-patient-button': return True, no_update, "", ""
    if ctx.triggered_id == 'submit-new-patient-button':
        if not name or not dob: return True, no_update, "", "Error: Name and DOB are required."
        if session and 'username' in session:
            create_patient(name, dob, con, ins, session['username'])
            updated_patients = fetch_patients(session['username'], session['role']).to_dict('records')
            return False, updated_patients, f"Patient {name} created.", ""
        else: return True, no_update, "", "Error: User session not found."
    return is_open, no_update, "", ""

@app.callback(
    Output('document-table', 'data', allow_duplicate=True),
    [Input('page-content', 'children'), Input('submit-upload-pdf-button', 'n_clicks'), 
     Input('confirm-delete-doc-button', 'n_clicks'), Input('sharing-save-status', 'children')],
    [State('url', 'search'), State('user-session', 'data')],
    prevent_initial_call=True
)
def load_document_list(content, n_upload, n_delete, share_status, search, session):
    """
    Loads or refreshes the list of documents for the currently viewed patient.
    Triggers on page load, after a PDF upload, or after a document deletion.
    """
    patient_id = parse_qs(urlparse(search).query).get('patient_id', [None])[0]
    if patient_id and session and 'username' in session:
        return fetch_patient_documents(patient_id, session['username'], session['role']).to_dict('records')
    return no_update

# --- Document Viewer and Comment Section Callbacks ---

@app.callback(
    Output('document-viewer-output', 'children'),
    Output('comment-section', 'children'),
    Output('viewed-document-store', 'data'),
    Input('document-table', 'active_cell'),
    [State('document-table', 'data'), State('user-session', 'data')],
    prevent_initial_call=True
)
def display_document_and_comments(active_cell, table_data, session):
    """
    Displays the content of a selected document and its associated comment section
    when a user clicks a row in the document table.
    """
    if not active_cell: return "Click a document to view its contents.", [html.H4("Comments"), html.P("Select a document to see comments.")], no_update
    
    doc_id = table_data[active_cell['row']]['id']
    doc_type, doc_data, creator = fetch_single_document(doc_id)
    viewer_content, action_buttons = [html.H4("Document Details", style={'borderBottom': '2px solid #ddd', 'paddingBottom': '5px'})], []
    
    # Build the document viewer content.
    if creator: viewer_content.append(html.P(f"Created by: {creator}", style={'fontStyle': 'italic', 'color': 'gray', 'fontSize': '0.9em'}))
    
    # Add Edit/Delete buttons based on user permissions.
    can_edit = session.get('role') == 'admin' or session.get('username') == creator
    if can_edit and doc_type != "PDF Upload":
        action_buttons.append(dcc.Link(dbc.Button("Edit Document", color="primary", size="sm", className="me-2"), href=f"/edit-doc?doc_id={doc_id}"))
    if session.get('role') == 'admin':
        action_buttons.append(dbc.Button("Delete Document", id="delete-doc-btn", color="danger", size="sm"))
    if action_buttons: viewer_content.append(html.Div(action_buttons, style={'marginBottom': '15px'}))
    
    # Display content differently for PDF uploads vs. form-based documents.
    if doc_type == "PDF Upload":
        viewer_content.append(html.A(doc_data.get('display_name', 'Download File'), href=f"/download/{doc_data.get('filename')}", target="_blank"))
    elif doc_data:
        for key, value in {k:v for k,v in doc_data.items() if k!='edit_history'}.items():
            viewer_content.append(html.P([html.B(f"{key.replace('_', ' ').title()}: "), ', '.join(value) if isinstance(value, list) else str(value)]))
    else:
        viewer_content.append(html.P("Error: Could not retrieve document."))
    
    # Display the edit history if it exists.
    if edit_history := doc_data.get('edit_history', []):
        history_content = [html.Hr(), html.H5("Edit History")]
        for entry in edit_history:
            history_content.append(html.P(f"- Edited by {entry['edited_by']} on {entry['edited_at']}", style={'fontSize': '0.8em', 'color': 'gray'}))
        viewer_content.extend(history_content)
    
    # Build the comment section.
    comment_area = [
        html.H4("Comments"),
        html.Div(id='comment-list', children=generate_comment_list(doc_id, session.get('role')), style={'maxHeight': '300px', 'overflowY': 'auto', 'border': '1px solid #ccc', 'padding': '10px', 'marginBottom': '10px'}),
        html.Div(id='comment-input-area', style={'display': 'block'}, children=[
            dcc.Textarea(id='comment-input', placeholder="Add a comment...", style=textarea_style),
            html.Button('Submit Comment', id='submit-comment-button', n_clicks=0, className="btn btn-primary")
        ])
    ]
    
    return html.Div(viewer_content), comment_area, {'doc_id': doc_id}

@app.callback(
    Output('document-viewer-output', 'children', allow_duplicate=True),
    Output('comment-section', 'children', allow_duplicate=True),
    Input('confirm-delete-doc-button', 'n_clicks'),
    State('viewed-document-store', 'data'),
    prevent_initial_call=True
)
def handle_document_deletion(n_clicks, doc_store):
    """Handles the final confirmation of a document deletion."""
    if doc_id := doc_store.get('doc_id'):
        delete_document(doc_id)
    return "Document deleted. Select another document.", []

def save_file(name, content):
    """Decodes and saves an uploaded file to the server with a unique filename."""
    data = content.encode("utf8").split(b";base64,")[1]
    # Generate a unique filename to prevent overwrites and conflicts.
    secure_filename = f"{uuid.uuid4()}{os.path.splitext(name)[1]}"
    with open(os.path.join(UPLOAD_DIRECTORY, secure_filename), "wb") as fp:
        fp.write(base64.decodebytes(data))
    return secure_filename

@app.callback(
    Output('upload-pdf-error-msg', 'children', allow_duplicate=True),
    Input('submit-upload-pdf-button', 'n_clicks'),
    [State('upload-pdf-display-name', 'value'), State('upload-pdf-component', 'filename'), 
     State('upload-pdf-component', 'contents'), State('url', 'search'), State('user-session', 'data')],
    prevent_initial_call=True
)
def handle_pdf_upload(n, display_name, filename, contents, search, session):
    """Handles the submission of the PDF upload form."""
    if not display_name: return "Error: Document Display Name is required."
    if not filename or not contents: return "Error: You must select a file to upload."
    if not (session and 'username' in session): return "Error: Could not identify user."
    
    patient_id = parse_qs(urlparse(search).query).get('patient_id', [None])[0]
    secure_filename = save_file(filename, contents)
    create_document(patient_id, 'PDF Upload', datetime.now().date(), {'filename': secure_filename, 'display_name': display_name}, session['username'])
    
    return "Upload successful!"

@app.callback(
    Output('comment-list', 'children', allow_duplicate=True),
    Output('comment-input', 'value'),
    Input('submit-comment-button', 'n_clicks'),
    State('comment-input', 'value'),
    State('viewed-document-store', 'data'),
    State('user-session', 'data'),
    prevent_initial_call=True
)
def submit_new_comment(n_clicks, text, doc_store, session):
    """Handles the submission of a new comment."""
    if not text or not doc_store: return no_update, no_update
    doc_id, username, role = doc_store.get('doc_id'), session.get('username'), session.get('role')
    add_comment(doc_id, username, text)
    # Regenerate the comment list and clear the input box.
    return generate_comment_list(doc_id, role), ""

def generate_comment_list(doc_id, user_role):
    """A helper function to generate the HTML for the list of comments."""
    comments = fetch_comments(doc_id)
    if not comments: return [html.P("No comments yet.")]
    children = []
    for c in comments:
        admin_buttons = []
        # Admins get edit and delete buttons on every comment.
        if user_role == 'admin':
            admin_buttons = [
                dbc.Button("Edit", id={'type': 'edit-comment-btn', 'index': c['id']}, color="link", size="sm", className="ms-2"),
                dbc.Button("Delete", id={'type': 'delete-comment-btn', 'index': c['id']}, color="link", size="sm", className="text-danger")
            ]
        children.append(html.Div([
            html.P([html.B(f"{c['username']} "), html.Span(f"({c['created_at']})", style={'fontSize': '0.8em', 'color': 'gray'}), *admin_buttons], className="mb-0"),
            html.P(c['comment_text'], style={'whiteSpace': 'pre-wrap'})
        ], style={'borderBottom': '1px solid #eee', 'padding': '8px 0'}))
    return children

@app.callback(
    Output('comment-list', 'children', allow_duplicate=True),
    Input({'type': 'delete-comment-btn', 'index': ALL}, 'n_clicks'),
    State('viewed-document-store', 'data'),
    State('user-session', 'data'),
    prevent_initial_call=True
)
def handle_delete_comment(n_clicks, doc_store, session):
    """
    A pattern-matching callback to handle the deletion of ANY comment.
    'ALL' allows this to listen to clicks from all delete buttons.
    `ctx.triggered_id` is used to identify which specific button was clicked.
    """
    if not any(n_clicks) or not doc_store: return no_update
    delete_comment(ctx.triggered_id['index'])
    return generate_comment_list(doc_store.get('doc_id'), session.get('role'))

@app.callback(
    Output('edit-comment-modal', 'is_open'),
    Output('edit-comment-textarea', 'value'),
    Output('comment-edit-store', 'data'),
    Input({'type': 'edit-comment-btn', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
)
def open_edit_modal(n_clicks):
    """Opens the 'Edit Comment' modal and pre-fills it with the comment's current text."""
    if not any(n_clicks): return no_update, no_update, no_update
    comment_id = ctx.triggered_id['index']
    return True, fetch_single_comment(comment_id), {'comment_id': comment_id}

@app.callback(
    Output('comment-list', 'children', allow_duplicate=True),
    Output('edit-comment-modal', 'is_open', allow_duplicate=True),
    Input('save-comment-button', 'n_clicks'),
    State('edit-comment-textarea', 'value'),
    State('comment-edit-store', 'data'),
    State('viewed-document-store', 'data'),
    State('user-session', 'data'),
    prevent_initial_call=True
)
def save_edited_comment(n_clicks, new_text, edit_store, doc_store, session):
    """Saves the changes to an edited comment."""
    update_comment(edit_store.get('comment_id'), new_text)
    # Refresh the comment list and close the modal.
    return generate_comment_list(doc_store.get('doc_id'), session.get('role')), False

# --- Form Submission Callbacks ---

@app.callback(
    Output('output-form-message', 'children', allow_duplicate=True),
    Input('submit-eval-button', 'n_clicks'),
    [State('current-patient-id', 'data'), State('current-document-id', 'data'), State('eval-date', 'date'), State('eval-physician', 'value'), State('eval-diag-codes', 'value'), State('eval-subjective', 'value'), State('eval-objective', 'value'), State('eval-problem', 'value'), State('eval-rehab-potential', 'value'), State('eval-goals', 'value'), State('eval-plan', 'value'), State('eval-frequency', 'value'), State('user-session', 'data')],
    prevent_initial_call=True
)
def submit_evaluation(n, pid, doc_id, d, phy, codes, subj, obj, prob, pot, goals, plan, freq, session):
    """Gathers data from the evaluation form and saves it as a new document or updates an existing one."""
    if not d: return "Error: Date of Service is required."
    if not (session and 'username' in session): return "Error: User session not found."
    data = {"Referring Physician": phy, "Diagnosis Codes": codes, "Subjective Notes": subj, "Objective Notes": obj, "Problem Statement": prob, "Rehab Potential": pot, "Goals": goals, "Plan of Care": plan, "Frequency": freq}
    if doc_id:
        update_document(doc_id, data, session['username'])
    else:
        create_document(pid, 'Evaluation', d, data, session['username'])
    return html.Div(["Document Saved! ", dcc.Link("Return to Patient Details", href=f"/patient-detail?patient_id={pid}")])

@app.callback(
    Output('output-form-message', 'children', allow_duplicate=True),
    Input('submit-treat-button', 'n_clicks'),
    [State('current-patient-id', 'data'), State('current-document-id', 'data'), State('treat-date', 'date'), State('treat-duration', 'value'), State('treat-subjective', 'value'), State('treat-objective', 'value'), State('treat-progress', 'value'), State('treat-goals', 'value'), State('treat-plan', 'value'), State('treat-education', 'value'), State('user-session', 'data')],
    prevent_initial_call=True
)
def submit_treatment(n, pid, doc_id, d, dur, subj, obj, prog, goals, plan, edu, session):
    """Gathers data from the treatment note form and saves it."""
    if not d: return "Error: Date of Service is required."
    if not (session and 'username' in session): return "Error: User session not found."
    data = {"Service Duration": dur, "Subjective Notes": subj, "Objective Notes": obj, "Progress Toward Goals": prog, "Updated Goals": goals, "Plan for Next Session": plan, "Patient Education": edu}
    if doc_id:
        update_document(doc_id, data, session['username'])
    else:
        create_document(pid, 'Treatment', d, data, session['username'])
    return html.Div(["Document Saved! ", dcc.Link("Return to Patient Details", href=f"/patient-detail?patient_id={pid}")])

@app.callback(
    Output('output-form-message', 'children', allow_duplicate=True),
    Input('submit-dis-button', 'n_clicks'),
    [State('current-patient-id', 'data'), State('current-document-id', 'data'), State('dis-date', 'date'), State('dis-summary', 'value'), State('dis-goals', 'value'), State('dis-reason', 'value'), State('dis-reason-custom', 'value'), State('dis-plan', 'value'), State('user-session', 'data')],
    prevent_initial_call=True
)
def submit_discharge(n, pid, doc_id, d, summ, goals, r, custom, plan, session):
    """Gathers data from the discharge summary form and saves it."""
    if not d: return "Error: Date of Discharge is required."
    if not (session and 'username' in session): return "Error: User session not found."
    full_reason = (r or []) + ([custom] if custom else [])
    data = {"Summary of Care": summ, "Goal Status at Discharge": goals, "Reason for Discharge": full_reason, "Discharge Plan": plan}
    if doc_id:
        update_document(doc_id, data, session['username'])
    else:
        create_document(pid, 'Discharge', d, data, session['username'])
    return html.Div(["Document Saved! ", dcc.Link("Return to Patient Details", href=f"/patient-detail?patient_id={pid}")])

# --- 5. RUN THE APP ---
if __name__ == '__main__':
    # Initialize the database before starting the app.
    init_db()
    # Run the Dash app server.
    # `host='0.0.0.0'` makes the server accessible on your local network.
    app.run(debug=False, host='0.0.0.0', port=8050) 
    # Use `app.run(debug=True)` for development to enable hot-reloading and error pages.
    