// This code is taken from https://github.com/Fullscreen/iam-authorized-keys-command
// Its responsibility is to query iam service for users that match criteria, and list them with ssh public keys
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type Config struct {
	IAMGroup    string
	AWSProfile  string
	SSHUsername string
}

type UserKey struct {
	Username    string
	PubKey      string
	Fingerprint string
}

type IAMKeyFetcher struct {
	config *Config
	wg     *sync.WaitGroup

	userCh chan<- *UserKey
	errCh  chan<- error
	doneCh chan<- bool
}

func (u *UserKey) String() string {
	return fmt.Sprintf("# %s\n%s\n", u.Username, u.PubKey)
}

const (
	exitCodeOk    int = 0
	exitCodeError int = 1

	MaxPageSize = 1000
)

var (
	cfg       = &Config{}
	verbosity int

	cmd = &cobra.Command{
		Use:  "iam-authorized-keys",
		Args: cobra.MaximumNArgs(1),
		RunE: FetchIAMSSHKeys,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			switch verbosity {
			case 0:
				// Nothing to do
			case 1:
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
			case 2: //nolint:gomnd
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			default:
				zerolog.SetGlobalLevel(zerolog.TraceLevel)
			}

			return nil
		},
	}
)

func main() {
	ctx := context.Background()
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	l := log.Output(os.Stderr)
	ctx = l.WithContext(ctx)

	cmd.Flags().StringVarP(&cfg.IAMGroup, "iam-group", "i", "", "Get SSH keys from this IAM group")
	cmd.Flags().StringVarP(&cfg.AWSProfile, "aws-profile", "p", "", "Connect to the specified AWS profile")
	cmd.Flags().CountVarP(&verbosity, "verbose", "v", "Print more verbose logging")

	if err := cmd.ExecuteContext(ctx); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("Error occurred")
		os.Exit(exitCodeError)
	}
}

// The main function of the Root command
func FetchIAMSSHKeys(cmd *cobra.Command, args []string) error {
	// Handle SIGPIPE
	//
	// When sshd identifies a key in the stdout of this command, it closes
	// the pipe causing a series of EPIPE errors before a SIGPIPE is emitted
	// on this scripts pid. If the script exits with the standard 13 code, sshd
	// will disregard any matched keys. We catch the signal here and exit 0 to
	// fix that problem.
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGPIPE)
	userCh := make(chan *UserKey)
	errCh := make(chan error)
	doneCh := make(chan bool)

	ctx := cmd.Context()
	f := &IAMKeyFetcher{
		config: cfg,
		wg:     &sync.WaitGroup{},
		userCh: userCh,
		errCh:  errCh,
		doneCh: doneCh,
	}

	log.Info().Msg("Starting IAM Fetch")

	if len(args) == 1 {
		go f.FetchPubKeyForUser(cmd.Context(), args[0])
	} else {
		go f.Fetch(cmd.Context())
	}

	for {
		select {
		case <-c:
			os.Exit(exitCodeOk)
		case err := <-errCh:
			log.Ctx(ctx).Error().Err(err).Msg("Error occurred")
			os.Exit(exitCodeError)
		case userKey := <-userCh:
			fmt.Print(userKey)
		case <-doneCh:
			os.Exit(exitCodeOk)
		}
	}
}

func (ikf *IAMKeyFetcher) Fetch(ctx context.Context) {
	log.Ctx(ctx).Debug().Msg("Started IAM Key Fetcher")
	iamClient, err := ikf.getIAMClient(ctx)
	if err != nil {
		ikf.errCh <- err
		return
	}

	users, err := ikf.listUsers(ctx, iamClient)
	if err != nil {
		ikf.errCh <- err
		return
	}

	log.Ctx(ctx).Debug().Interface("users", users).Msg("Fetched users")

	for _, u := range users {
		ikf.wg.Add(1)
		go ikf.fetchPubKey(ctx, iamClient, u)
	}
	ikf.wg.Wait()
	ikf.doneCh <- true
	close(ikf.userCh)
}

// FetchPubKeyForUser fetches the public key for the user specified on the command line
func (ikf *IAMKeyFetcher) FetchPubKeyForUser(ctx context.Context, userName string) {
	log.Ctx(ctx).Debug().Str("username", userName).Msg("Started IAM Key Fetcher")
	iamClient, err := ikf.getIAMClient(ctx)
	if err != nil {
		ikf.errCh <- err
		return
	}

	user, err := iamClient.GetUser(ctx, &iam.GetUserInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("username", userName).Msg("Failed to fetch user")
		ikf.errCh <- err
		return
	}

	log.Ctx(ctx).Debug().Str("username", userName).Msg("Fetched user")

	if user.User.UserName == nil {
		log.Ctx(ctx).Error().Str("username", userName).Msg("User has no username")
		return
	}

	if user.User.Arn == nil {
		log.Ctx(ctx).Error().Str("username", userName).Msg("User has no ARN")
		return
	}

	ikf.wg.Add(1) // fetchPubKey will decrement this
	ikf.fetchPubKey(ctx, iamClient, *user.User)
	ikf.doneCh <- true
	close(ikf.userCh)
}

// getIAMClient returns a newly configured IAM client
func (ikf *IAMKeyFetcher) getIAMClient(ctx context.Context) (*iam.Client, error) {
	awsConfig, err := config.LoadDefaultConfig(ctx)

	if err != nil {
		return nil, err
	}

	svc := iam.NewFromConfig(awsConfig)
	return svc, nil
}

func (ikf *IAMKeyFetcher) fetchPubKey(ctx context.Context, svc *iam.Client, user types.User) {
	params := &iam.ListSSHPublicKeysInput{
		UserName: user.UserName,
	}

	log.Ctx(ctx).Debug().Str("username", *user.UserName).Str("arn", *user.Arn).Msg("Fetching keys")

	if resp, err := svc.ListSSHPublicKeys(ctx, params); err == nil {
		for _, k := range resp.SSHPublicKeys {
			if k.Status != types.StatusTypeActive {
				continue
			}

			params := &iam.GetSSHPublicKeyInput{
				Encoding:       types.EncodingTypeSsh,
				SSHPublicKeyId: k.SSHPublicKeyId,
				UserName:       user.UserName,
			}

			resp, err := svc.GetSSHPublicKey(ctx, params)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Str("username", *user.UserName).Str("ssh-key-id", *k.SSHPublicKeyId).Msg("Failed to fetch key")
			}

			ikf.userCh <- &UserKey{
				Username:    *user.UserName,
				PubKey:      *resp.SSHPublicKey.SSHPublicKeyBody,
				Fingerprint: *resp.SSHPublicKey.Fingerprint,
			}
		}
	} else {
		log.Ctx(ctx).Error().Err(err).Str("username", *user.UserName).Msg("Failed to list keys")
	}
	ikf.wg.Done()
}

// get all IAM users, or just those that are part of the defined group
func (ikf *IAMKeyFetcher) listUsers(ctx context.Context, svc *iam.Client) ([]types.User, error) {
	if ikf.config.IAMGroup != "" {
		params := &iam.GetGroupInput{
			GroupName: aws.String(ikf.config.IAMGroup),
			MaxItems:  aws.Int32(MaxPageSize),
		}

		resp, err := svc.GetGroup(ctx, params)
		if err != nil {
			return nil, err
		}

		return resp.Users, nil
	}

	params := &iam.ListUsersInput{
		MaxItems: aws.Int32(MaxPageSize),
	}

	resp, err := svc.ListUsers(ctx, params)
	if err != nil {
		return nil, err
	}

	return resp.Users, nil
}
