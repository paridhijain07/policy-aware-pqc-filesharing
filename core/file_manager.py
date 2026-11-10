"""
Chunked File Storage and Transfer Management.
Handles atomic file assembly, SHA-256 verification, and chunk resumption offsets.
"""

import os
import hashlib
from typing import Generator, Tuple, Optional


class FileManager:
    """Manages chunked file reading, writing, and resumption verification."""

    CHUNK_SIZE = 64 * 1024  # 64 KB

    @staticmethod
    def get_file_info(file_path: str) -> Tuple[int, int, str]:
        """
        Returns (file_size, total_chunks, sha256_hex) for a given file.
        """
        file_size = os.path.getsize(file_path)
        total_chunks = (file_size + FileManager.CHUNK_SIZE - 1) // FileManager.CHUNK_SIZE if file_size > 0 else 1

        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(FileManager.CHUNK_SIZE):
                h.update(chunk)

        return file_size, total_chunks, h.hexdigest()

    @staticmethod
    def read_chunks(file_path: str, start_chunk: int = 0) -> Generator[Tuple[int, bytes, bool], None, None]:
        """
        Yields (chunk_index, chunk_bytes, is_final) starting from start_chunk.
        """
        file_size = os.path.getsize(file_path)
        total_chunks = (file_size + FileManager.CHUNK_SIZE - 1) // FileManager.CHUNK_SIZE if file_size > 0 else 1

        with open(file_path, "rb") as f:
            if start_chunk > 0:
                f.seek(start_chunk * FileManager.CHUNK_SIZE)

            for index in range(start_chunk, total_chunks):
                data = f.read(FileManager.CHUNK_SIZE)
                is_final = (index == total_chunks - 1)
                yield index, data, is_final

    @staticmethod
    def write_partial_chunk(storage_dir: str, file_name: str, chunk_index: int, chunk_data: bytes) -> str:
        """
        Writes decrypted chunk data into a temporary assembly file.
        """
        os.makedirs(storage_dir, exist_ok=True)
        partial_path = os.path.join(storage_dir, f"{file_name}.part")
        
        mode = "r+b" if os.path.exists(partial_path) else "w+b"
        with open(partial_path, mode) as f:
            f.seek(chunk_index * FileManager.CHUNK_SIZE)
            f.write(chunk_data)

        return partial_path

    @staticmethod
    def finalize_file(storage_dir: str, file_name: str, expected_sha256: str) -> str:
        """
        Validates SHA-256 of assembled file and moves it from .part to final destination.
        """
        partial_path = os.path.join(storage_dir, f"{file_name}.part")
        final_path = os.path.join(storage_dir, file_name)

        if not os.path.exists(partial_path):
            raise FileNotFoundError(f"Partial assembly file not found: {partial_path}")

        h = hashlib.sha256()
        with open(partial_path, "rb") as f:
            while chunk := f.read(FileManager.CHUNK_SIZE):
                h.update(chunk)

        calculated_hash = h.hexdigest()
        if calculated_hash.lower() != expected_sha256.lower():
            raise ValueError(
                f"File integrity verification failed! Expected SHA-256 {expected_sha256}, got {calculated_hash}"
            )

        if os.path.exists(final_path):
            os.remove(final_path)
        os.rename(partial_path, final_path)
        return final_path

