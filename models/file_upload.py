import os

class FileUpload:
    def __init__(self, upload_dir):
        """
        Initialize the FileUpload class with a directory to store uploaded files.
        :param upload_dir: Directory where files will be uploaded.
        """
        self.upload_dir = upload_dir
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)

    def save_file(self, file, filename):
        """
        Save the uploaded file to the upload directory.
        :param file: File-like object to be saved.
        :param filename: Name of the file to save as.
        :return: Full path to the saved file.
        """
        file_path = os.path.join(self.upload_dir, filename)
        with open(file_path, 'wb') as f:
            f.write(file.read())
        return file_path

    def list_files(self):
        """
        List all files in the upload directory.
        :return: List of filenames in the upload directory.
        """
        return os.listdir(self.upload_dir)

    def delete_file(self, filename):
        """
        Delete a file from the upload directory.
        :param filename: Name of the file to delete.
        :return: True if the file was deleted, False if the file does not exist.
        """
        file_path = os.path.join(self.upload_dir, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False