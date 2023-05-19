class GithubCommitsController < ApplicationController

  unloadable

  skip_before_action :check_if_login_required
  skip_before_action :verify_authenticity_token

  before_action :verify_signature?

  GITHUB_URL                  = "https://github.com/"
  REDMINE_JOURNALIZED_TYPE    = "Issue"
  REDMINE_ISSUE_NUMBER_PREFIX = "#rm"

  def create_comment
    resp_json = nil
    if params[:commits].present?
      params[:commits].each do |commit|
        author       = commit.dig(:author, :name)
        author_email = commit.dig(:author, :email)
        message      = commit[:message]

        if message.present? && is_commit_to_be_tracked?(commit)
          admin = User.where(admin: true).first

          issues_from(message).each do |issue|
            user_email = EmailAddress.find_by(address: author_email)
            user       = user_email.present? ? user_email.user : admin
            notes      = t('commit.message',
                           author:     author,
                           message:    message,
                           commit_id:  commit[:id],
                           commit_url: commit[:url])
            issue.journals.create(journalized_id:   issue.id,
                                  journalized_type: REDMINE_JOURNALIZED_TYPE,
                                  user:             user,
                                  notes:            notes)
          end
          resp_json = { success: true }
        else
          resp_json = { success: false, error: t('labels.no_issue_found') }
        end
      end
    elsif params[:pull_request].present?
      author    = params.dig(:pull_request, :user, :login)
      message   = params.dig(:pull_request, :title)
      pr_number = params.dig(:pull_request, :number)
      pr_state  = params.dig(:pull_request, :state)
      pr_url    = params.dig(:pull_request, :html_url)

      if message.present? && message.include?(REDMINE_ISSUE_NUMBER_PREFIX)
        admin = User.where(admin: true).first

        issues_from(message).each do |issue|
          notes = t('pull_request.message',
                    author:    author,
                    message:   message,
                    pr_number: pr_number,
                    pr_state:  pr_state,
                    pr_url:    pr_url)
          issue.journals.create(journalized_id:   issue.id,
                                journalized_type: REDMINE_JOURNALIZED_TYPE,
                                user:             admin,
                                notes:            notes)
        end
        resp_json = { success: true }
      else
        resp_json = { success: false, error: t('labels.no_issue_found') }
      end
    else
      resp_json = { success: false, error: t('labels.no_data_found') }
    end

    respond_to do |format|
      format.json { render json: resp_json, status: :ok }
    end

  end

  def verify_signature?
    if request.env['HTTP_X_HUB_SIGNATURE'].blank? || ENV["GITHUB_SECRET_TOKEN"].blank?
      render json: { success: false }, status: 500
    else
      request.body.rewind
      payload_body = request.body.read
      signature    = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), ENV["GITHUB_SECRET_TOKEN"], payload_body)
      render json: { success: false }, status: 500 unless Rack::Utils.secure_compare(signature, request.env['HTTP_X_HUB_SIGNATURE'])
    end
  end

  private

  def is_commit_to_be_tracked?(commit_obj)
    commit_obj[:distinct] == true && # is it a fresh commit ?
      commit_obj[:message].to_s.include?(REDMINE_ISSUE_NUMBER_PREFIX) # Does it include the redmine issue prefix string pattern?
  end

  def issues_from(message)
    Issue.where(id: message.to_s.scan(/#{REDMINE_ISSUE_NUMBER_PREFIX}(\d+)/).flatten.map(&:to_i))
  end
end
