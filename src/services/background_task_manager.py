"""
Background Task Manager Service.
Handles interval-based tasks like key rotation scheduling.
"""

import threading
import time
import logging
from typing import Dict, Any, Optional, Callable
from datetime import datetime


class BackgroundTaskManager:
    """Manages background tasks and interval scheduling."""
    
    def __init__(self):
        """Initialize background task manager."""
        self.logger = logging.getLogger(__name__)
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.task_lock = threading.Lock()
        self.running = True
        
        # Start the task monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_tasks, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("Background task manager initialized")
    
    def start_interval_task(self, task_id: str, task_func: Callable, interval_minutes: int, *args, **kwargs) -> bool:
        """
        Start a task that runs at the specified interval.
        
        Args:
            task_id: Unique identifier for the task
            task_func: Function to execute
            interval_minutes: Interval in minutes
            *args: Arguments to pass to the task function
            **kwargs: Keyword arguments to pass to the task function
            
        Returns:
            bool: True if task started successfully
        """
        with self.task_lock:
            if task_id in self.tasks:
                self.logger.warning(f"Task {task_id} already exists")
                return False
            
            self.tasks[task_id] = {
                'task_func': task_func,
                'interval_minutes': interval_minutes,
                'interval_seconds': interval_minutes * 60,
                'args': args,
                'kwargs': kwargs,
                'last_run': None,
                'next_run': time.time(),
                'running': True,
                'created_at': datetime.now(),
                'run_count': 0
            }
            
            self.logger.info(f"Started interval task {task_id} with {interval_minutes} minute interval")
            return True
    
    def stop_task(self, task_id: str) -> bool:
        """
        Stop a running task.
        
        Args:
            task_id: Task identifier to stop
            
        Returns:
            bool: True if task was stopped successfully
        """
        with self.task_lock:
            if task_id not in self.tasks:
                self.logger.warning(f"Task {task_id} not found")
                return False
            
            self.tasks[task_id]['running'] = False
            self.logger.info(f"Stopped task {task_id}")
            return True
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a specific task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Dict containing task status or None if not found
        """
        with self.task_lock:
            if task_id not in self.tasks:
                return None
            
            task = self.tasks[task_id].copy()
            task['task_func'] = str(task['task_func'])  # Convert function to string for display
            return task
    
    def list_tasks(self) -> Dict[str, Dict[str, Any]]:
        """
        Get list of all tasks.
        
        Returns:
            Dict of all tasks with their status
        """
        with self.task_lock:
            tasks_copy = {}
            for task_id, task in self.tasks.items():
                task_copy = task.copy()
                task_copy['task_func'] = str(task_copy['task_func'])  # Convert function to string
                tasks_copy[task_id] = task_copy
            return tasks_copy
    
    def _monitor_tasks(self):
        """Monitor and execute tasks at their scheduled intervals."""
        while self.running:
            current_time = time.time()
            tasks_to_run = []
            
            # Check which tasks need to run
            with self.task_lock:
                for task_id, task in self.tasks.items():
                    if task['running'] and current_time >= task['next_run']:
                        tasks_to_run.append(task_id)
            
            # Execute tasks that are due
            for task_id in tasks_to_run:
                self._execute_task(task_id)
            
            # Sleep for a short interval before checking again
            time.sleep(1)
    
    def _execute_task(self, task_id: str):
        """Execute a specific task."""
        with self.task_lock:
            if task_id not in self.tasks or not self.tasks[task_id]['running']:
                return
            
            task = self.tasks[task_id]
        
        try:
            self.logger.info(f"Executing task {task_id}")
            
            # Execute the task function
            task['task_func'](*task['args'], **task['kwargs'])
            
            # Update task status
            with self.task_lock:
                if task_id in self.tasks and self.tasks[task_id]['running']:
                    self.tasks[task_id]['last_run'] = datetime.now()
                    self.tasks[task_id]['next_run'] = time.time() + task['interval_seconds']
                    self.tasks[task_id]['run_count'] += 1
                    
                    self.logger.info(f"Task {task_id} completed successfully (run #{self.tasks[task_id]['run_count']})")
        
        except Exception as e:
            self.logger.error(f"Error executing task {task_id}: {e}")
            
            # Update task status even on error
            with self.task_lock:
                if task_id in self.tasks and self.tasks[task_id]['running']:
                    self.tasks[task_id]['last_run'] = datetime.now()
                    self.tasks[task_id]['next_run'] = time.time() + task['interval_seconds']
                    self.tasks[task_id]['run_count'] += 1
    
    def shutdown(self):
        """Shutdown the background task manager."""
        self.logger.info("Shutting down background task manager")
        self.running = False
        
        # Stop all tasks
        with self.task_lock:
            for task_id in list(self.tasks.keys()):
                self.tasks[task_id]['running'] = False
        
        # Wait for monitor thread to finish
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)


# Global instance
background_task_manager = BackgroundTaskManager()
