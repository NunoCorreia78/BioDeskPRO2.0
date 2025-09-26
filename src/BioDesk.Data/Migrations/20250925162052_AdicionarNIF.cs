using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AdicionarNIF : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "NIF",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 9,
                nullable: false,
                defaultValue: "");

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 11, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 11, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 18, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 18, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 15, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 15, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 27, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 22, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm", "NIF" },
                values: new object[] { new DateTime(2025, 9, 23, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 8, 26, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), "" });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm", "NIF" },
                values: new object[] { new DateTime(2025, 9, 20, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 8, 31, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), "" });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm", "NIF" },
                values: new object[] { new DateTime(2025, 9, 24, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 5, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), "" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "NIF",
                table: "Pacientes");

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 11, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 9, 11, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 18, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 9, 18, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 15, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 9, 15, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 27, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 9, 22, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 23, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 8, 26, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 20, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 8, 31, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 24, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 9, 5, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });
        }
    }
}
