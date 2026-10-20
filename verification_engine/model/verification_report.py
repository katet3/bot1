# verification_engine/model/verification_report.py

from dataclasses import (
    dataclass,
    field
)

from verification_engine.model.verification_error import (
    VerificationError
)


@dataclass
class VerificationReport:
    """
    Итоговый отчёт верификации.

    success=True
        -> CFG корректен

    success=False
        -> найдены ошибки
    """

    success: bool = True

    errors: list[
        VerificationError
    ] = field(
        default_factory=list
    )

    def add_error(
        self,
        error: VerificationError
    ) -> None:
        """
        Добавляет ошибку
        в отчёт.
        """
        self.success = False

        self.errors.append(error)

    def extend(
        self,
        errors: list[
            VerificationError
        ]
    ) -> None:
        """
        Добавляет список ошибок.
        """
        if errors:
            self.success = False

            self.errors.extend(errors)

    def merge(
        self,
        other: "VerificationReport"
    ) -> None:
        """
        Объединяет два отчёта.
        """
        if not other.success:
            self.success = False

        self.errors.extend(
            other.errors
        )

    def has_errors(self) -> bool:
        return len(self.errors) > 0

    def summary(self) -> str:
        """
        Краткая сводка
        для CI.
        """
        if self.success:
            return (
                "Verification PASSED "
                "(0 errors)"
            )

        return (
            f"Verification FAILED "
            f"({len(self.errors)} errors)"
        )

    def to_text(self) -> str:
        """
        Полный текстовый отчёт.
        """
        lines = [self.summary()]

        if self.errors:
            lines.append("")
            lines.append("Errors:")

            for error in self.errors:
                lines.append(
                    f" - {error}"
                )

        return "\n".join(lines)

    def __str__(self):
        return self.to_text()