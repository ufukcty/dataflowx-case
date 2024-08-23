from enum import Enum

class StatusEnum(Enum):
    STATUS_CREATED = 1
    STATUS_INPROGRESS = 2
    STATUS_COMPLETED = 3
    STATUS_RESCAN = 4
    
    def get_name(self) -> str:
        status_names = {
            StatusEnum.STATUS_CREATED: "created",
            StatusEnum.STATUS_INPROGRESS: "inprogress",
            StatusEnum.STATUS_COMPLETED: "completed",
            StatusEnum.STATUS_RESCAN: "rescan",
        }
        return status_names.get(self, "Unknown")