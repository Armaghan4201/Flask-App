import sqlite3

def empty_event_table(db_path):
    """
    Empties all records from the event table in the specified SQLite database.
    
    Args:
        db_path (str): Path to the SQLite database file
    """
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Execute DELETE statement to remove all records from the event table
        cursor.execute("DELETE FROM event")
        
        # Commit the changes
        conn.commit()
        
        # Get the number of rows deleted
        deleted_count = cursor.rowcount
        print(f"Successfully deleted {deleted_count} records from the event table.")
        
        # Close the connection
        conn.close()
        print("Database connection closed.")
        
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

# Usage
if __name__ == "__main__":
    # Replace with the path to your database file
    database_path = "app.db"
    empty_event_table(database_path)