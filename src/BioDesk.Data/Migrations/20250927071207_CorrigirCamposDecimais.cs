using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class CorrigirCamposDecimais : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<decimal>(
                name: "Peso",
                table: "Pacientes",
                type: "decimal(5,2)",
                nullable: true,
                oldClrType: typeof(decimal),
                oldType: "TEXT",
                oldNullable: true);

            migrationBuilder.AlterColumn<decimal>(
                name: "Altura",
                table: "Pacientes",
                type: "decimal(5,2)",
                nullable: true,
                oldClrType: typeof(decimal),
                oldType: "TEXT",
                oldNullable: true);

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 13, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 13, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 20, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 20, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 17, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 17, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 29, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 24, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 22, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 19, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 30, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 25, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 7,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 10, 7, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 26, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 25, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 8, 28, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 22, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 2, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 26, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 7, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 26, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146), new DateTime(2025, 9, 12, 8, 12, 7, 93, DateTimeKind.Local).AddTicks(5146) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<decimal>(
                name: "Peso",
                table: "Pacientes",
                type: "TEXT",
                nullable: true,
                oldClrType: typeof(decimal),
                oldType: "decimal(5,2)",
                oldNullable: true);

            migrationBuilder.AlterColumn<decimal>(
                name: "Altura",
                table: "Pacientes",
                type: "TEXT",
                nullable: true,
                oldClrType: typeof(decimal),
                oldType: "decimal(5,2)",
                oldNullable: true);

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 13, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 13, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 20, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 20, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 17, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 17, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 29, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 24, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 22, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 19, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 30, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 25, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 7,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 10, 7, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 26, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 25, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 8, 28, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 22, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 2, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 26, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 7, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 26, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237), new DateTime(2025, 9, 12, 8, 1, 8, 14, DateTimeKind.Local).AddTicks(1237) });
        }
    }
}
