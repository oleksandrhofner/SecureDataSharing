using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureDataSharing.Data.Migrations
{
    /// <inheritdoc />
    public partial class UpdateUserDeletionCascades : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AuditLogs_AspNetUsers_UserId",
                table: "AuditLogs");

            migrationBuilder.DropIndex(
                name: "IX_DataPermissions_StoredDataId_RecipientUserId",
                table: "DataPermissions");

            migrationBuilder.CreateIndex(
                name: "IX_DataPermissions_StoredDataId",
                table: "DataPermissions",
                column: "StoredDataId");

            migrationBuilder.AddForeignKey(
                name: "FK_AuditLogs_AspNetUsers_UserId",
                table: "AuditLogs",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AuditLogs_AspNetUsers_UserId",
                table: "AuditLogs");

            migrationBuilder.DropIndex(
                name: "IX_DataPermissions_StoredDataId",
                table: "DataPermissions");

            migrationBuilder.CreateIndex(
                name: "IX_DataPermissions_StoredDataId_RecipientUserId",
                table: "DataPermissions",
                columns: new[] { "StoredDataId", "RecipientUserId" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_AuditLogs_AspNetUsers_UserId",
                table: "AuditLogs",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id");
        }
    }
}
