using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDeclaracaoSaudeTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeclaracoesSaude",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataUltimaAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: true),
                    TemDiabetes = table.Column<bool>(type: "INTEGER", nullable: false),
                    TemHipertensao = table.Column<bool>(type: "INTEGER", nullable: false),
                    TemCardiopatias = table.Column<bool>(type: "INTEGER", nullable: false),
                    TemAlergias = table.Column<bool>(type: "INTEGER", nullable: false),
                    TemOutrasDoencas = table.Column<bool>(type: "INTEGER", nullable: false),
                    EspecificacaoOutrasDoencas = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    SuplementosAlimentares = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    MedicamentosNaturais = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    DoencasHereditarias = table.Column<string>(type: "TEXT", nullable: true),
                    ObservacoesFamiliares = table.Column<string>(type: "TEXT", nullable: true),
                    Tabagismo = table.Column<string>(type: "TEXT", nullable: false),
                    DetalheTabagismo = table.Column<string>(type: "TEXT", nullable: true),
                    ConsumoAlcool = table.Column<string>(type: "TEXT", nullable: false),
                    DetalheAlcool = table.Column<string>(type: "TEXT", nullable: true),
                    ExercicioFisico = table.Column<string>(type: "TEXT", nullable: false),
                    DetalheExercicio = table.Column<string>(type: "TEXT", nullable: true),
                    HorasSono = table.Column<int>(type: "INTEGER", nullable: false),
                    QualidadeSono = table.Column<string>(type: "TEXT", nullable: false),
                    TipoDieta = table.Column<string>(type: "TEXT", nullable: false),
                    RestricaoesAlimentares = table.Column<string>(type: "TEXT", nullable: true),
                    ConsumoAguaDiario = table.Column<decimal>(type: "TEXT", nullable: false),
                    ConfirmoVeracidade = table.Column<bool>(type: "INTEGER", nullable: false),
                    CompreendoImportancia = table.Column<bool>(type: "INTEGER", nullable: false),
                    ComprometoInformarAlteracoes = table.Column<bool>(type: "INTEGER", nullable: false),
                    ObservacoesAdicionais = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeclaracoesSaude", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeclaracoesSaude_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AlergiaAlimentar",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DeclaracaoSaudeId = table.Column<int>(type: "INTEGER", nullable: false),
                    Alimento = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ReacaoConhecida = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlergiaAlimentar", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AlergiaAlimentar_DeclaracoesSaude_DeclaracaoSaudeId",
                        column: x => x.DeclaracaoSaudeId,
                        principalTable: "DeclaracoesSaude",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AlergiaAmbiental",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DeclaracaoSaudeId = table.Column<int>(type: "INTEGER", nullable: false),
                    Alergenio = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Sintomas = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlergiaAmbiental", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AlergiaAmbiental_DeclaracoesSaude_DeclaracaoSaudeId",
                        column: x => x.DeclaracaoSaudeId,
                        principalTable: "DeclaracoesSaude",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AlergiaMedicamentosa",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DeclaracaoSaudeId = table.Column<int>(type: "INTEGER", nullable: false),
                    Medicamento = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Severidade = table.Column<string>(type: "TEXT", nullable: false),
                    Reacao = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlergiaMedicamentosa", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AlergiaMedicamentosa_DeclaracoesSaude_DeclaracaoSaudeId",
                        column: x => x.DeclaracaoSaudeId,
                        principalTable: "DeclaracoesSaude",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Cirurgia",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DeclaracaoSaudeId = table.Column<int>(type: "INTEGER", nullable: false),
                    Data = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TipoCirurgia = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Hospital = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Cirurgia", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Cirurgia_DeclaracoesSaude_DeclaracaoSaudeId",
                        column: x => x.DeclaracaoSaudeId,
                        principalTable: "DeclaracoesSaude",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "HistoriaFamiliar",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DeclaracaoSaudeId = table.Column<int>(type: "INTEGER", nullable: false),
                    GrauParentesco = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    CondicaoDoenca = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    IdadeDiagnostico = table.Column<int>(type: "INTEGER", nullable: true),
                    Status = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HistoriaFamiliar", x => x.Id);
                    table.ForeignKey(
                        name: "FK_HistoriaFamiliar_DeclaracoesSaude_DeclaracaoSaudeId",
                        column: x => x.DeclaracaoSaudeId,
                        principalTable: "DeclaracoesSaude",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Hospitalizacao",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DeclaracaoSaudeId = table.Column<int>(type: "INTEGER", nullable: false),
                    Data = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Motivo = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    DuracaoDias = table.Column<int>(type: "INTEGER", nullable: false),
                    Hospital = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Hospitalizacao", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Hospitalizacao_DeclaracoesSaude_DeclaracaoSaudeId",
                        column: x => x.DeclaracaoSaudeId,
                        principalTable: "DeclaracoesSaude",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "IntoleranciaAlimentar",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DeclaracaoSaudeId = table.Column<int>(type: "INTEGER", nullable: false),
                    Alimento = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Sintomas = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IntoleranciaAlimentar", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IntoleranciaAlimentar_DeclaracoesSaude_DeclaracaoSaudeId",
                        column: x => x.DeclaracaoSaudeId,
                        principalTable: "DeclaracoesSaude",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MedicamentoAtual",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DeclaracaoSaudeId = table.Column<int>(type: "INTEGER", nullable: false),
                    Nome = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Dosagem = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Frequencia = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    DesdeQuando = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MedicamentoAtual", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MedicamentoAtual_DeclaracoesSaude_DeclaracaoSaudeId",
                        column: x => x.DeclaracaoSaudeId,
                        principalTable: "DeclaracoesSaude",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 2, 11, 12, 39, 719, DateTimeKind.Utc).AddTicks(9416));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 17, 11, 12, 39, 719, DateTimeKind.Utc).AddTicks(9432));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 25, 11, 12, 39, 719, DateTimeKind.Utc).AddTicks(9437));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 2, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(42), new DateTime(2025, 9, 2, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(27) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(52), new DateTime(2025, 9, 9, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(48) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(62), new DateTime(2025, 9, 22, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(57) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 17, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(73), new DateTime(2025, 9, 17, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(68) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 1, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(83), new DateTime(2025, 10, 1, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(79) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(94), new DateTime(2025, 9, 27, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(90) });

            migrationBuilder.CreateIndex(
                name: "IX_AlergiaAlimentar_DeclaracaoSaudeId",
                table: "AlergiaAlimentar",
                column: "DeclaracaoSaudeId");

            migrationBuilder.CreateIndex(
                name: "IX_AlergiaAmbiental_DeclaracaoSaudeId",
                table: "AlergiaAmbiental",
                column: "DeclaracaoSaudeId");

            migrationBuilder.CreateIndex(
                name: "IX_AlergiaMedicamentosa_DeclaracaoSaudeId",
                table: "AlergiaMedicamentosa",
                column: "DeclaracaoSaudeId");

            migrationBuilder.CreateIndex(
                name: "IX_Cirurgia_DeclaracaoSaudeId",
                table: "Cirurgia",
                column: "DeclaracaoSaudeId");

            migrationBuilder.CreateIndex(
                name: "IX_DeclaracoesSaude_PacienteId",
                table: "DeclaracoesSaude",
                column: "PacienteId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_HistoriaFamiliar_DeclaracaoSaudeId",
                table: "HistoriaFamiliar",
                column: "DeclaracaoSaudeId");

            migrationBuilder.CreateIndex(
                name: "IX_Hospitalizacao_DeclaracaoSaudeId",
                table: "Hospitalizacao",
                column: "DeclaracaoSaudeId");

            migrationBuilder.CreateIndex(
                name: "IX_IntoleranciaAlimentar_DeclaracaoSaudeId",
                table: "IntoleranciaAlimentar",
                column: "DeclaracaoSaudeId");

            migrationBuilder.CreateIndex(
                name: "IX_MedicamentoAtual_DeclaracaoSaudeId",
                table: "MedicamentoAtual",
                column: "DeclaracaoSaudeId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AlergiaAlimentar");

            migrationBuilder.DropTable(
                name: "AlergiaAmbiental");

            migrationBuilder.DropTable(
                name: "AlergiaMedicamentosa");

            migrationBuilder.DropTable(
                name: "Cirurgia");

            migrationBuilder.DropTable(
                name: "HistoriaFamiliar");

            migrationBuilder.DropTable(
                name: "Hospitalizacao");

            migrationBuilder.DropTable(
                name: "IntoleranciaAlimentar");

            migrationBuilder.DropTable(
                name: "MedicamentoAtual");

            migrationBuilder.DropTable(
                name: "DeclaracoesSaude");

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 8, 31, 16, 0, 53, 894, DateTimeKind.Utc).AddTicks(1352));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 15, 16, 0, 53, 894, DateTimeKind.Utc).AddTicks(1362));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 23, 16, 0, 53, 894, DateTimeKind.Utc).AddTicks(1366));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 8, 31, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1655), new DateTime(2025, 8, 31, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1646) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 7, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1663), new DateTime(2025, 9, 7, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1659) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 20, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1674), new DateTime(2025, 9, 20, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1667) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 15, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1682), new DateTime(2025, 9, 15, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1678) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 29, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1688), new DateTime(2025, 9, 29, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1685) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 25, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1742), new DateTime(2025, 9, 25, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1738) });
        }
    }
}
