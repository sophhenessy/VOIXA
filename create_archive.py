#!/usr/bin/env python3
import os
import zipfile
import datetime
import sys

def create_project_archive():
    """Create a ZIP archive of the project's core files with a timestamp."""
    
    # Get current timestamp for the filename
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_name = f"project_backup_{timestamp}.zip"
    
    # Define directories and files to include
    dirs_to_include = ["client", "db", "server"]
    root_files_to_include = [f for f in os.listdir(".") if os.path.isfile(f) and 
                             f.endswith((".ts", ".js", ".json", ".md"))]
    
    print(f"Creating project archive: {archive_name}")
    print(f"Including directories: {', '.join(dirs_to_include)}")
    print(f"Including root files: {', '.join(root_files_to_include)}")
    
    # Create the archive
    with zipfile.ZipFile(archive_name, "w", zipfile.ZIP_DEFLATED) as zipf:
        # Add root files
        for file in root_files_to_include:
            if os.path.exists(file):
                zipf.write(file)
        
        # Add directories
        for dir_name in dirs_to_include:
            if os.path.exists(dir_name):
                for root, dirs, files in os.walk(dir_name):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if not file_path.startswith("node_modules/"):
                            zipf.write(file_path)
            else:
                print(f"Warning: Directory {dir_name} not found")
    
    # Verify the ZIP was created successfully
    if os.path.exists(archive_name):
        size_mb = os.path.getsize(archive_name) / (1024 * 1024)
        print(f"Archive created successfully: {archive_name} ({size_mb:.2f} MB)")
        print("You can download this file from the Files panel in Replit.")
        return True
    else:
        print("Error: Failed to create archive")
        return False

if __name__ == "__main__":
    create_project_archive()